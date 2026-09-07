import json
import os
import sys
from dataclasses import replace
import unittest
from unittest import mock

import test_onboarding_proof as shared
import test_proof_controller as controller_tests
import linux_blender_proof as linux

proof = shared.proof


class PlatformInstallIntegrationTests(unittest.TestCase):
    def test_hosted_install_refuses_before_native_admission_import(self):
        fixture = shared.ProofFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        request = replace(fixture.request, proof="host-install", execution="hosted", driver_sha="b" * 40)
        authority = object()
        with mock.patch.dict(os.environ, GITHUB_RUN_ATTEMPT="1"), \
                mock.patch.dict(sys.modules, {"proof_controller_worker": None}), \
                mock.patch.object(proof.InstallOperator, "load") as load, \
                mock.patch.object(proof.Commands, "run") as command:
            result = proof.baseline(request, native_authority=authority)
        self.assertEqual(result["outcomes"]["preparation"]["code"], "hosted-recovery-retention-unavailable")
        self.assertIsNone(result["run"])
        load.assert_not_called()
        command.assert_not_called()

    def test_install_rejects_linux_and_custom_windows_adapter_before_operator_load(self):
        fixture = shared.ProofFixture()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)

        class CustomWindowsHost(proof.WindowsProofHost):
            pass

        for host in (linux.LinuxProofHost(), CustomWindowsHost()):
            with self.subTest(host=type(host).__name__), \
                    mock.patch.object(proof.InstallOperator, "load") as load, \
                    mock.patch.object(proof.Commands, "run") as command:
                request = replace(fixture.request, proof="host-install", output=fixture.root / type(host).__name__)
                result = proof.baseline(request, host=host)
                self.assertEqual(result["outcomes"]["preparation"]["code"], "candidate-invalid")
                load.assert_not_called()
                command.assert_not_called()

    @unittest.skipUnless(controller_tests.controller.fcntl is not None, "POSIX private controller files")
    def test_named_target_native_admission_retains_catalog_recovery_and_cleanup(self):
        fixture = controller_tests.ControllerTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.policy = replace(fixture.policy, variant="named-target")
        running = fixture.reopen().dispatch(controller_tests.command(variant="named-target"))
        self.assertEqual(running["phase"], "running")
        self.assertFalse(fixture.factory.instances)
        fixture.service.complete(fixture.worker)
        result = fixture.reopen().dispatch(controller_tests.command("status"))
        self.assertEqual(result["phase"], "settled")
        self.assertEqual(result["proof_result"], "pass")
        self.assertEqual(result["windows_cleanup"], "proven")
        outcome = json.loads((fixture.jobs / "gha_123_1/baseline/public/outcome.json").read_bytes())
        self.assertEqual(outcome["proof"], "windows-onboarding-named-target")
        self.assertTrue(all(outcome["outcomes"][name]["status"] == "pass" for name in proof.NAMED_REQUIRED))
        commands = fixture.factory.instances[0]
        self.assertFalse(any(call[1:3] == ["windows", "setup"] and "--apply" in call for call in commands.calls))
        self.assertEqual(commands.targets, {})
