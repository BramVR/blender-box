from pathlib import Path
import subprocess
import sys
import unittest


class ProofDiscoveryTests(unittest.TestCase):
    def test_discovery_without_posix_modules_keeps_portable_contracts(self):
        script = """
import sys
import unittest

sys.modules['resource'] = None
sys.modules['fcntl'] = None
loader = unittest.TestLoader()
suite = unittest.TestSuite([
    loader.discover('tests/ci', pattern='test_proof_controller*.py'),
    loader.discover('tests/ci', pattern='test_proof_adoption.py'),
    loader.discover('tests/ci', pattern='test_platform_install_integration.py'),
    loader.discover('tests/ci', pattern='test_qualification*.py'),
])
assert not loader.errors, '\\n'.join(loader.errors)
assert 'proof_controller_worker' not in sys.modules
required = {
    'test_platform_install_integration.PlatformInstallIntegrationTests.test_hosted_install_refuses_before_native_admission_import',
    'test_platform_install_integration.PlatformInstallIntegrationTests.test_install_rejects_linux_and_custom_windows_adapter_before_operator_load',
    'test_proof_controller.WireAndCLITests.test_request_exact_keys_bounds_and_duplicates',
    'test_proof_controller.WireAndCLITests.test_dispatch_never_reflects_input_or_starts_anything',
    'test_proof_controller_native.NativeParsingTests.test_unit_parser_rejects_partial_duplicate_and_inconsistent_identity',
    'test_proof_controller_native.NativeParsingTests.test_native_receipt_only_accepts_unique_fixed_subtree',
    'test_proof_controller_native.NativeCLITests.test_scp_pin_and_tmpfiles_binding_are_required',
    'test_proof_controller_native.NativeCLITests.test_false_or_wrong_binding_refuses_before_any_native_mutation',
    'test_qualification_contract.QualificationContractTests.test_linux_hash_domains_and_three_way_selector_rejection',
    'test_qualification_contract.QualificationContractTests.test_exact_shapes_duplicate_keys_versions_boolean_numbers_and_size',
    'test_qualification_contract.QualificationContractTests.test_authorization_file_hash_and_execution_identity_have_different_roles',
    'test_qualification_contract.QualificationContractTests.test_operational_dispatch_never_accepts_qualification_document',
    'test_qualification_driver.LocalQualificationDriverTests.test_local_driver_sha_does_not_select_hold',
    'test_qualification_driver.HoldFixtureTests.test_fixed_hold_timeout_fails_without_a_success_result',
}
pending = list(suite)
discovered = set()
while pending:
    case = pending.pop()
    if isinstance(case, unittest.TestSuite):
        pending.extend(case)
    else:
        discovered.add(case.id())
assert required <= discovered, required - discovered
result = unittest.TextTestRunner(verbosity=2).run(suite)
skipped = {case.id() for case, reason in result.skipped}
assert required.isdisjoint(skipped), required & skipped
assert result.wasSuccessful()
assert 'proof_controller_worker' not in sys.modules
"""
        result = subprocess.run([sys.executable, "-c", script],
                                cwd=Path(__file__).resolve().parents[2],
                                capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
