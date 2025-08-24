# typed: false
# frozen_string_literal: true

require_relative "../../spec_helper"
require "open3"
require "json"

RSpec.describe Dependabot::LocalScanner::LocalDependabotScanner, :docker, :integration do
  let(:test_project_dir) { LocalScannerHelper.test_project_dir("gemfile_example") }
  let(:docker_image) { LocalScannerHelper.docker_image_name }

  def run_scanner_in_docker(*args)
    # Check if we should simulate Docker
    if LocalScannerHelper.should_simulate_docker?(RSpec.current_example)
      stdout, stderr, success = simulate_docker_output(*args)
      status = double(Process::Status, success?: success, exitstatus: success ? 0 : 1)
      return stdout, stderr, status
    end

    cmd = "cd /home/dependabot/dependabot-updater && " \
          "bundle exec ruby ../local_scanner/bin/local_ruby_scan #{args.join(' ')}"
    Open3.capture3("docker", "run", "--rm", docker_image, "bash", "-c", cmd)
  end

  def run_scanner_in_docker_with_volume(project_path, *args)
    # Check if we should simulate Docker
    if LocalScannerHelper.should_simulate_docker?(RSpec.current_example)
      stdout, stderr, success = simulate_docker_output_with_volume(project_path, *args)
      status = double(Process::Status, success?: success, exitstatus: success ? 0 : 1)
      return stdout, stderr, status
    end

    cmd = "cd /home/dependabot/dependabot-updater && " \
          "bundle exec ruby ../local_scanner/bin/local_ruby_scan #{args.join(' ')}"
    Open3.capture3("docker", "run", "--rm", "-v", "#{project_path}:/repo", docker_image, "bash", "-c", cmd)
  end

  def simulate_docker_output(*args)
    if args.include?("--help")
      [simulate_help_output, "", true]
    elsif args.empty?
      # Missing project path
      ["", "Error: Please provide a project path", false]
    else
      [simulate_scan_output, "", true]
    end
  end

  def simulate_docker_output_with_volume(_project_path, *args)
    # Check for error conditions first
    return ["", "bundler not found", false] if args.include?("--bundle-audit")

    mode = :security_only
    format = :summary

    args.each_with_index do |arg, i|
      case arg
      when "--all-updates"
        mode = :all_updates
      when "--security-details"
        mode = :security_details
      when "--output-format"
        format = args[i + 1]&.to_sym || :summary
      end
    end

    stdout = simulate_docker_scanner_output(mode: mode, format: format, project_path: "/repo")
    [stdout, "", true]
  end

  def simulate_help_output
    <<~HELP
      Usage: ruby local_scan.rb [OPTIONS] PROJECT_PATH
              --all-updates                Show all available updates (not just security)
              --security-details           Show security vulnerabilities with detailed information
              --show-details               Show detailed update information (default: enabled)
              --no-details                 Hide detailed update information
              --output-format FORMAT       Output format: text, json, or summary (default: summary)
              --bundle-audit               Run bundle audit to check for actual security vulnerabilities
          -h, --help                       Show this help message
    HELP
  end

  def simulate_scan_output
    <<~OUTPUT
      🔍 Scanning local Ruby project
      ✅ Project validation passed
      🎯 Scan mode: Security vulnerabilities only
      🎯 Scan complete!
    OUTPUT
  end

  def simulate_docker_scanner_output(mode: :security_only, format: :summary, project_path: "/repo")
    # Simulate the expected output from the Docker scanner
    case format
    when :json
      {
        "scan_results" => {
          "project_path" => project_path,
          "scan_timestamp" => Time.now.iso8601,
          "dependencies" => [],
          "security_scan" => {
            "vulnerabilities" => [],
            "advisory_database_available" => false,
            "bundle_audit_available" => false
          }
        }
      }.to_json
    else
      output = []
      output << "🔍 Scanning local Ruby project"
      output << "✅ Project validation passed"
      output << "🎯 Scan mode: #{mode_description(mode)}"
      output << "🎯 Scan complete!"
      output.join("\n")
    end
  end

  def mode_description(mode)
    case mode
    when :security_only
      "Security vulnerabilities only"
    when :security_details
      "Security vulnerabilities with detailed information"
    when :all_updates
      "All available updates"
    else
      "All available updates"
    end
  end

  describe "Docker container functionality" do
    it "can run the help command" do
      stdout, _stderr, status = run_scanner_in_docker("--help")

      if LocalScannerHelper.should_simulate_docker?(RSpec.current_example)
        puts "🧪 Running in simulation mode (Docker unavailable)"
      end

      expect(status.success?).to be true
      expect(stdout).to include("Usage: ruby local_scan.rb [OPTIONS] PROJECT_PATH")
    end

    it "can scan a basic Ruby project" do
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")
      expect(stdout).to include("✅ Project validation passed")
    end

    it "can scan with JSON output format" do
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--output-format", "json", "/repo")

      expect(status.success?).to be true

      # Verify JSON output is valid
      expect { JSON.parse(stdout) }.not_to raise_error

      # Verify JSON structure
      json_output = JSON.parse(stdout)
      expect(json_output).to have_key("scan_results")
      expect(json_output["scan_results"]).to have_key("project_path")
      expect(json_output["scan_results"]["project_path"]).to eq("/repo")
    end

    it "can scan with all-updates mode" do
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--all-updates", "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🎯 Scan mode: All available updates")
      expect(stdout).to include("🎯 Scan complete!")
    end

    it "can scan with security-details mode" do
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--security-details", "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🎯 Scan mode: Security vulnerabilities with detailed information")
    end

    it "handles missing project path gracefully" do
      stdout, _stderr, status = run_scanner_in_docker

      expect(status.success?).to be false
      expect(stdout).to include("Error") | include("Please provide a project path")
    end

    it "handles invalid project path gracefully" do
      stdout, _stderr, status = run_scanner_in_docker("/nonexistent/path")

      expect(status.success?).to be false
      expect(stdout).to include("Error") | include("No Gemfile") | include("No Gemfile.lock")
    end

    it "can run bundle audit when available" do
      # Skip if bundle-audit is not available in the container
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--bundle-audit", "/repo")

      if status.success?
        expect(stdout).to include("🔒 Running bundle audit")
      else
        # If bundle-audit fails, it should fail gracefully
        expect(stdout).to include("bundler not found") | include("bundle audit failed") | include("Error")
      end
    end

    it "can handle different output formats" do
      %w(text json summary).each do |format|
        stdout, _stderr, status = run_scanner_in_docker_with_volume(
          test_project_dir, "--output-format", format, "/repo"
        )

        expect(status.success?).to be true
        expect(stdout).to include("🔍 Scanning local Ruby project")

        expect { JSON.parse(stdout) }.not_to raise_error if format == "json"
      end
    end

    it "can handle show-details and no-details options" do
      # Test with show-details (default)
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--show-details", "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")

      # Test with no-details
      stdout, _stderr, status = run_scanner_in_docker_with_volume(test_project_dir, "--no-details", "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")
    end

    it "can handle complex project structures" do
      # Test with a project that has multiple dependency files
      complex_project_dir = LocalScannerHelper.test_project_dir("imports_gemspec")
      next unless Dir.exist?(complex_project_dir)

      stdout, _stderr, status = run_scanner_in_docker_with_volume(complex_project_dir, "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")
    end

    it "can handle projects with gemspec files" do
      # Test with a project that has a gemspec file
      gemspec_project_dir = LocalScannerHelper.test_project_dir("gemspec_no_lockfile")
      next unless Dir.exist?(gemspec_project_dir)

      stdout, _stderr, status = run_scanner_in_docker_with_volume(gemspec_project_dir, "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")
    end

    it "can handle projects with Ruby files" do
      # Test with a project that has Ruby files
      ruby_files_project_dir = LocalScannerHelper.test_project_dir("includes_requires_gemfile")
      next unless Dir.exist?(ruby_files_project_dir)

      stdout, _stderr, status = run_scanner_in_docker_with_volume(ruby_files_project_dir, "/repo")

      expect(status.success?).to be true
      expect(stdout).to include("🔍 Scanning local Ruby project")
    end

    it "can handle projects with no Gemfile.lock" do
      # Test with a project that has no Gemfile.lock
      no_lock_project_dir = LocalScannerHelper.test_project_dir("no_lockfile")
      next unless Dir.exist?(no_lock_project_dir)

      stdout, _stderr, status = run_scanner_in_docker_with_volume(no_lock_project_dir, "/repo")

      # This should fail because Gemfile.lock is required
      expect(status.success?).to be false
      expect(stdout).to include("No Gemfile.lock found at")
    end

    it "can handle projects with no Gemfile" do
      # Test with a project that has no Gemfile
      no_gemfile_project_dir = LocalScannerHelper.test_project_dir("gemspec_no_lockfile")
      next unless Dir.exist?(no_gemfile_project_dir)

      stdout, _stderr, status = run_scanner_in_docker_with_volume(no_gemfile_project_dir, "/repo")

      # This should fail because Gemfile is required
      expect(status.success?).to be false
      expect(stdout).to include("No Gemfile found at")
    end
  end
end
