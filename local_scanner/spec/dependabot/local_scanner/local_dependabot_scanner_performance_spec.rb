# typed: false
# frozen_string_literal: true

require_relative "../../spec_helper"
require "benchmark"

RSpec.describe Dependabot::LocalScanner::LocalDependabotScanner, :performance do
  let(:test_project_dir) { LocalScannerHelper.test_project_dir("basic_ruby_project") }
  let(:scanner) { described_class.new(test_project_dir) }

  describe "startup performance" do
    it "starts up within acceptable time limits" do
      times = []
      5.times do
        time = Benchmark.realtime do
          new_scanner = described_class.new(test_project_dir)
          expect(new_scanner).to be_a(described_class)
        end
        times << time
      end

      average_time = times.sum / times.length

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        # More lenient expectations for containerized environments
        expect(average_time).to be < 0.5 # Average startup under 0.5 seconds in container
        expect(times.max).to be < 1.0    # No single startup over 1 second in container
      else
        # Stricter expectations for native environments
        expect(average_time).to be < 0.1 # Average startup under 0.1 seconds
        expect(times.max).to be < 0.2    # No single startup over 0.2 seconds
      end
    end
  end

  describe "scan performance" do
    it "completes basic scan within acceptable time" do
      time = Benchmark.realtime do
        result = scanner.scan_dependencies
        expect(result).to be_a(Hash)
        expect(result).to have_key("dependencies")
      end

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        expect(time).to be < 2.0 # Basic scan under 2 seconds in container
      else
        expect(time).to be < 1.0 # Basic scan under 1 second
      end
    end

    it "completes security scan within acceptable time" do
      time = Benchmark.realtime do
        result = scanner.scan_security_vulnerabilities
        expect(result).to be_a(Hash)
        expect(result).to have_key("security_scan")
      end

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        expect(time).to be < 2.0 # Security scan under 2 seconds in container
      else
        expect(time).to be < 1.0 # Security scan under 1 second
      end
    end

    it "completes all-updates scan within acceptable time" do
      time = Benchmark.realtime do
        result = scanner.generate_report(format: :text)
        expect(result).to be_a(String)
        expect(result).to include("Project Path:")
      end

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        expect(time).to be < 2.0 # All-updates scan under 2 seconds in container
      else
        expect(time).to be < 1.0 # All-updates scan under 1 second
      end
    end
  end

  describe "memory usage" do
    it "maintains reasonable memory usage during scan" do
      # This is a basic check - in a real environment you'd use more sophisticated tools
      start_memory = `ps -o rss= -p #{Process.pid}`.to_i

      result = scanner.scan_dependencies
      expect(result).to be_a(Hash)

      end_memory = `ps -o rss= -p #{Process.pid}`.to_i
      memory_increase = end_memory - start_memory

      # Memory increase should be reasonable (less than 50MB)
      expect(memory_increase).to be < 50 * 1024
    end
  end

  describe "concurrent performance" do
    it "handles multiple concurrent scans efficiently" do
      # Run multiple scans simultaneously using threads
      results = []
      threads = []

      3.times do
        threads << Thread.new do
          new_scanner = described_class.new(test_project_dir)
          result = new_scanner.scan_dependencies
          results << { status: :success, result: result }
        rescue StandardError => e
          results << { status: :error, error: e.message }
        end
      end

      threads.each(&:join)

      # All scans should succeed
      successful_scans = results.select { |r| r[:status] == :success }
      expect(successful_scans.length).to eq(3)

      # All results should be valid
      successful_scans.each do |scan|
        expect(scan[:result]).to be_a(Hash)
        expect(scan[:result]).to have_key("dependencies")
      end
    end

    it "maintains performance under load" do
      # Test that performance doesn't degrade with multiple scans
      times = []

      5.times do
        time = Benchmark.realtime do
          new_scanner = described_class.new(test_project_dir)
          new_scanner.scan_dependencies
        end
        times << time
      end

      average_time = times.sum / times.length

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        # More lenient expectations for containerized environments
        expect(average_time).to be < 1.0 # Average time under 1 second in container
        # Use standard deviation for more robust performance consistency testing
        # Calculate coefficient of variation (CV = std_dev / mean)
        std_dev = Math.sqrt(times.sum { |t| (t - average_time)**2 } / times.length)
        coefficient_of_variation = std_dev / average_time
        # Performance should be reasonably consistent (CV < 150% in containers)
        # Container environments can have high variance due to shared resources
        expect(coefficient_of_variation).to be < 1.5
      else
        # Stricter expectations for native environments
        expect(average_time).to be < 0.1 # Average time under 0.1 seconds
        # Use standard deviation for more robust performance consistency testing
        std_dev = Math.sqrt(times.sum { |t| (t - average_time)**2 } / times.length)
        coefficient_of_variation = std_dev / average_time
        # Performance should be consistent (CV < 30% in native environments)
        expect(coefficient_of_variation).to be < 0.3
      end
    end
  end

  describe "resource efficiency" do
    it "does not leak file descriptors" do
      # Get initial file descriptor count
      initial_fds = begin
        Dir.glob("/proc/#{Process.pid}/fd/*").length
      rescue StandardError
        0
      end

      # Perform multiple operations
      5.times do
        scanner.scan_dependencies
        scanner.scan_security_vulnerabilities
        scanner.generate_report
      end

      # Get final file descriptor count
      final_fds = begin
        Dir.glob("/proc/#{Process.pid}/fd/*").length
      rescue StandardError
        0
      end

      # File descriptor count should not increase significantly
      fd_increase = final_fds - initial_fds
      expect(fd_increase).to be < 10
    end

    it "cleans up temporary resources" do
      # Test that creating multiple scanners doesn't cause resource buildup
      initial_memory = `ps -o rss= -p #{Process.pid}`.to_i

      scanners = []
      10.times do
        scanners << described_class.new(test_project_dir)
        scanners.last.scan_dependencies
      end

      # Clear references to allow garbage collection
      scanners.clear
      GC.start

      final_memory = `ps -o rss= -p #{Process.pid}`.to_i
      memory_increase = final_memory - initial_memory

      # Memory increase should be minimal after cleanup
      expect(memory_increase).to be < 20 * 1024 # Less than 20MB
    end
  end

  describe "report generation performance" do
    it "generates reports quickly" do
      time = Benchmark.realtime do
        result = scanner.generate_report(format: :json)
        expect(result).to be_a(String)
        expect { JSON.parse(result) }.not_to raise_error
      end

      # Adjust expectations based on environment
      if LocalScannerHelper.running_in_docker_container?
        expect(time).to be < 1.0 # Report generation under 1 second in container
      else
        expect(time).to be < 0.5 # Report generation under 0.5 seconds
      end
    end

    it "handles different output formats efficiently" do
      formats = %i(summary text json)

      formats.each do |format|
        time = Benchmark.realtime do
          result = scanner.generate_report(format: format)
          expect(result).to be_a(String)
        end

        # Adjust expectations based on environment
        if LocalScannerHelper.running_in_docker_container?
          expect(time).to be < 0.6 # Each format under 0.6 seconds in container
        else
          expect(time).to be < 0.3 # Each format under 0.3 seconds
        end
      end
    end
  end
end
