# typed: false
# frozen_string_literal: true

require "rspec"
require "tempfile"
require "fileutils"
require "open3"
require "json"
require "yaml"
require "benchmark"
require "socket"

# Add the lib directories to the load path for local testing
$LOAD_PATH.unshift(File.expand_path("../../common/lib", __dir__))
$LOAD_PATH.unshift(File.expand_path("../../bundler/lib", __dir__))
$LOAD_PATH.unshift(File.expand_path("../../updater/lib", __dir__))

# Load the local scanner
require_relative "../lib/dependabot/local_scanner"

module LocalScannerHelper
  def self.test_project_dir(project_name)
    # Use existing bundler fixtures from the main repo instead of local ones
    # Map test names to actual available fixtures
    fixture_mapping = {
      "basic_ruby_project" => "gemfile",
      "vulnerable_project" => "gemfile",
      "empty_project" => "gemspec_no_gemfile"
    }

    actual_fixture = fixture_mapping[project_name] || project_name
    File.expand_path("../../bundler/spec/fixtures/projects/bundler2/#{actual_fixture}", __dir__)
  end

  def self.docker_image_name
    # Try multiple possible image names
    possible_names = [
      "ghcr.io/dependabot/dependabot-updater-local_scanner:latest",
      "dependabot/dependabot-core-development-local_scanner:latest"
    ]

    possible_names.each do |name|
      return name if system("docker image inspect #{name} > /dev/null 2>&1")
    end

    # Default to the official name if none exist
    "ghcr.io/dependabot/dependabot-updater-local_scanner:latest"
  end

  def self.docker_available?
    # If we're inside a container (which we are when running tests), assume Docker is available
    return true if File.exist?("/.dockerenv")

    system("docker --version > /dev/null 2>&1")
  end

  def self.docker_image_exists?
    # If we're running inside the container, the image exists by definition
    return true if File.exist?("/.dockerenv")

    system("docker image inspect #{docker_image_name} > /dev/null 2>&1")
  end

  def self.build_docker_image
    puts "🏗️  Building local_scanner Docker image..."

    project_root = File.expand_path("../..", __dir__)
    remove_old_image
    latest_mod_time = calculate_latest_code_modification_time
    puts "📅 Latest code modification time: #{latest_mod_time}"

    return true if build_with_cache_busting(project_root, latest_mod_time)
    return true if build_with_direct_docker(project_root)
    return true if build_simple_test_image(project_root)

    puts "❌ Failed to build Docker image using all methods"
    puts "   This might be due to missing base images or authentication issues"
    puts "   Docker tests will be skipped"
    false
  end

  def self.remove_old_image
    puts "🗑️  Removing old Docker image to ensure fresh build..."
    system("docker rmi #{docker_image_name} 2>/dev/null")
  end

  def self.build_with_cache_busting(project_root, latest_mod_time)
    puts "📦 Building Docker image with cache-busting and no-cache..."
    puts "   Running: docker build with CODE_MODIFIED_TIME=#{latest_mod_time}"

    build_core_image_if_needed(project_root)

    build_cmd = "cd #{project_root} && docker build " \
                "--no-cache " \
                "--build-arg CODE_MODIFIED_TIME=#{latest_mod_time} " \
                "-f local_scanner/Dockerfile " \
                "-t #{docker_image_name} ."
    system(build_cmd)
  end

  def self.build_core_image_if_needed(project_root)
    return if system("docker images | grep -q dependabot-updater-core")

    puts "🔨 Building core image first..."
    system("cd #{project_root} && docker build -f Dockerfile.updater-core " \
           "-t ghcr.io/dependabot/dependabot-updater-core .")
  end

  def self.build_with_direct_docker(project_root)
    puts "🔄 script/build failed, trying direct docker build..."
    puts "   Note: This may fail if base images are not available"

    puts "📦 Building core updater image..."
    core_cmd = "cd #{project_root} && docker build -t ghcr.io/dependabot/dependabot-updater-core " \
               "-f Dockerfile.updater-core ."
    return false unless system(core_cmd)

    puts "📦 Building local_scanner image..."
    scanner_cmd = "cd #{project_root} && docker build -t #{docker_image_name} " \
                  "-f local_scanner/Dockerfile ."
    scanner_success = system(scanner_cmd)

    if scanner_success
      puts "✅ Docker image built successfully using direct docker build"
      return true
    end

    false
  end

  def self.build_simple_test_image(project_root)
    # Create a simple Dockerfile for testing
    dockerfile_content = <<~DOCKERFILE
      FROM ruby:3.4-slim

      # Install basic dependencies
      RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

      # Set up working directory
      WORKDIR /app

      # Copy the local scanner and dependencies
      COPY local_scanner /app/local_scanner
      COPY common /app/common
      COPY bundler /app/bundler

      # Set up the load path and entry point
      ENV RUBYLIB="/app/common/lib:/app/bundler/lib"
      WORKDIR /app/local_scanner

      # Default command
      CMD ["ruby", "bin/local_ruby_scan", "--help"]
    DOCKERFILE

    # Write the Dockerfile to a temporary location
    dockerfile_path = File.join(project_root, "Dockerfile.test-local-scanner")
    File.write(dockerfile_path, dockerfile_content)

    # Build the image
    build_cmd = "cd #{project_root} && docker build -t #{docker_image_name} " \
                "-f Dockerfile.test-local-scanner ."
    system(build_cmd)

    # Clean up the temporary Dockerfile
    FileUtils.rm_f(dockerfile_path)
  end

  def self.ensure_docker_image
    return true if docker_image_exists?
    return false unless docker_available?

    build_docker_image
  end

  def self.should_simulate_docker?(example)
    example.metadata[:simulate_docker] == true || running_in_docker_container?
  end

  def self.running_in_docker_container?
    # Check if we're running inside a Docker container
    # Look for common Docker container indicators
    File.exist?("/.dockerenv") ||
      (File.exist?("/proc/1/cgroup") && File.read("/proc/1/cgroup").include?("docker")) ||
      ENV["DOCKER_CONTAINER"] == "true" ||
      (ENV["CI"] == "true" && ENV["RUNNING_IN_CONTAINER"] == "true") ||
      # Check if hostname looks like a Docker container ID
      Socket.gethostname.match?(/^[a-f0-9]{12}$/) ||
      # Check if we're in the dependabot development container
      Socket.gethostname.include?("dependabot")
  end

  def self.should_rebuild_image?
    # Check if source files or Dockerfile are newer than the Docker image
    return true unless docker_image_exists?

    image_created = Time.parse(`docker inspect #{docker_image_name} --format='{{.Created}}' 2>/dev/null`.strip)
    source_files = [
      File.mtime(File.expand_path("../bin/local_ruby_scan", __dir__)),
      File.mtime(File.expand_path("../lib", __dir__)),
      File.mtime(File.expand_path("../Dockerfile", __dir__))
    ].max

    source_files > image_created
  rescue StandardError
    # If we can't determine timestamps, rebuild to be safe
    true
  end

  def self.calculate_latest_code_modification_time
    # Find all Ruby files and Dockerfile in local_scanner and get their modification times
    local_scanner_dir = File.expand_path("..", __dir__)
    ruby_files = Dir.glob("#{local_scanner_dir}/**/*.rb")
    dockerfile = File.expand_path("../Dockerfile", __dir__)

    all_files = ruby_files + [dockerfile]

    if all_files.empty?
      # Fallback to current time if no files found
      Time.now.to_i
    else
      # Get the latest modification time of all relevant files
      latest_time = all_files.map { |f| File.mtime(f) }.max
      latest_time.to_i
    end
  end
end

RSpec.configure do |config|
  config.color = true
  config.order = :random
  config.mock_with(:rspec) { |mocks| mocks.verify_partial_doubles = true }
  config.expect_with(:rspec) { |expectations| expectations.include_chain_clauses_in_custom_matcher_descriptions = true }
  config.raise_errors_for_deprecations!
  config.example_status_persistence_file_path = ".rspec_status"

  config.before(:suite) do
    # Check if we need to run Docker tests
    docker_tests_needed = RSpec.world.all_examples.any? { |example| example.metadata[:docker] }

    next unless docker_tests_needed

    unless LocalScannerHelper.docker_available?
      puts "⚠️  Docker not available - skipping Docker integration tests"
      next
    end

    # Check if we need to rebuild the Docker image
    if LocalScannerHelper.should_rebuild_image?
      puts "🔍 Docker image needs rebuilding (source files are newer), building automatically..."
      next unless LocalScannerHelper.build_docker_image

      puts "❌ Failed to build Docker image - Docker tests will be skipped"
    else
      puts "✅ Docker image is up to date"
    end
  end

  config.around do |example|
    if example.metadata[:docker]
      # Check if we're running in a container and should simulate Docker
      if LocalScannerHelper.running_in_docker_container?
        puts "🐳 Running in Docker container - switching to simulation mode"
        example.metadata[:simulate_docker] = true
        next
      end

      unless LocalScannerHelper.docker_available?
        skip "Docker not available"
        next
      end

      # Try to build the image if it doesn't exist
      unless LocalScannerHelper.docker_image_exists?
        puts "🔍 Docker image not found, attempting to build..."
        unless LocalScannerHelper.build_docker_image
          puts "⚠️  Docker build failed, switching to simulation mode"
          example.metadata[:simulate_docker] = true
        end
      end
    end

    example.run
  end
end
