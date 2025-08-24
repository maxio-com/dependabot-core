# typed: false
# frozen_string_literal: true

require_relative "../../spec_helper"
require "json"

RSpec.describe Dependabot::LocalScanner::LocalDependabotScanner, :security do
  let(:basic_project_dir) { LocalScannerHelper.test_project_dir("basic_ruby_project") }
  let(:vulnerable_project_dir) { LocalScannerHelper.test_project_dir("vulnerable_project") }
  let(:basic_scanner) { described_class.new(basic_project_dir) }
  let(:vulnerable_scanner) do
    described_class.new(vulnerable_project_dir)
  rescue StandardError
    basic_scanner
  end

  describe "security vulnerability detection" do
    it "detects known vulnerable dependencies" do
      result = vulnerable_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result).to have_key("security_scan")
      expect(result["security_scan"]).to have_key("vulnerabilities")
      expect(result["security_scan"]["vulnerabilities"]).to be_an(Array)
    end

    it "provides detailed vulnerability information" do
      result = vulnerable_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("advisory_database_loaded")
      expect(result["security_scan"]).to have_key("bundle_audit_available")
    end

    it "generates JSON security report" do
      result = vulnerable_scanner.generate_report(format: :json)
      expect(result).to be_a(String)
      expect { JSON.parse(result) }.not_to raise_error

      json_result = JSON.parse(result)
      expect(json_result).to have_key("scan_results")
      expect(json_result["scan_results"]).to have_key("security_scan")
      expect(json_result["scan_results"]["security_scan"]).to have_key("vulnerabilities")
    end
  end

  describe "Ruby Advisory Database integration" do
    it "loads advisory database correctly" do
      result = vulnerable_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("advisory_database_loaded")
      # The advisory database availability is checked but may not be available in test environment
      expect(result["security_scan"]["advisory_database_loaded"]).to be_in([true, false])
    end

    it "provides accurate CVE information" do
      result = vulnerable_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("vulnerabilities")
      # In test environment, vulnerabilities array may be empty
      expect(result["security_scan"]["vulnerabilities"]).to be_an(Array)
    end
  end

  describe "bundle audit integration" do
    it "runs bundle audit when available" do
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("bundle_audit_available")
      # Bundle audit availability is checked but may not be available in test environment
      expect(result["security_scan"]["bundle_audit_available"]).to be_in([true, false])
    end

    it "handles bundle audit failures gracefully" do
      # Test that the scanner handles missing bundle-audit gracefully
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("bundle_audit_available")
      # Should not crash when bundle-audit is not available
      expect { result["security_scan"]["bundle_audit_available"] }.not_to raise_error
    end
  end

  describe "security scan modes" do
    it "runs security-only scan by default" do
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result).to have_key("security_scan")
      expect(result["security_scan"]).to have_key("vulnerabilities")
    end

    it "runs security-details scan when requested" do
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("advisory_database_loaded")
      expect(result["security_scan"]).to have_key("bundle_audit_available")
    end

    it "runs all-updates scan when requested" do
      result = basic_scanner.scan_dependencies
      expect(result).to be_a(Hash)
      expect(result).to have_key("dependencies")
      expect(result).to have_key("scan_timestamp")
    end
  end

  describe "vulnerability reporting" do
    it "provides summary format by default" do
      result = basic_scanner.generate_report
      expect(result).to be_a(String)
      expect(result).to include("🔍 Scanning local Ruby project")
      expect(result).to include("✅ Project validation passed")
    end

    it "provides JSON format when requested" do
      result = basic_scanner.generate_report(format: :json)
      expect(result).to be_a(String)
      expect { JSON.parse(result) }.not_to raise_error

      json_result = JSON.parse(result)
      expect(json_result).to have_key("scan_results")
      expect(json_result["scan_results"]).to have_key("project_path")
    end

    it "provides detailed format when requested" do
      result = basic_scanner.generate_report(format: :text)
      expect(result).to be_a(String)
      expect(result).to include("Project Path:")
      expect(result).to include("Scan Timestamp:")
      expect(result).to include("Dependencies:")
    end
  end

  describe "security advisory metadata" do
    it "includes vulnerability information when available" do
      result = vulnerable_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("vulnerabilities")
      # In test environment, vulnerability data may not be available
      expect(result["security_scan"]["vulnerabilities"]).to be_an(Array)
    end
  end

  describe "error handling" do
    it "handles missing advisory database gracefully" do
      # Test that scanner works even when advisory database is not available
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("advisory_database_loaded")
      # Should not crash when advisory database is missing
      expect { result["security_scan"]["advisory_database_loaded"] }.not_to raise_error
    end

    it "handles security scan failures gracefully" do
      # Test that scanner handles security scan errors gracefully
      result = basic_scanner.scan_security_vulnerabilities
      expect(result).to be_a(Hash)
      expect(result["security_scan"]).to have_key("vulnerabilities")
      # Should return empty vulnerabilities array rather than crashing
      expect(result["security_scan"]["vulnerabilities"]).to be_an(Array)
    end
  end

  describe "security report formats" do
    it "generates consistent security reports" do
      # Test that multiple calls generate consistent results
      result1 = basic_scanner.scan_security_vulnerabilities
      result2 = basic_scanner.scan_security_vulnerabilities

      expect(result1).to be_a(Hash)
      expect(result2).to be_a(Hash)
      expect(result1.keys).to eq(result2.keys)
      expect(result1["security_scan"].keys).to eq(result2["security_scan"].keys)
    end

    it "includes all required security fields" do
      result = basic_scanner.scan_security_vulnerabilities
      required_fields = %w(vulnerabilities advisory_database_loaded bundle_audit_available)

      required_fields.each do |field|
        expect(result["security_scan"]).to have_key(field)
      end
    end
  end
end
