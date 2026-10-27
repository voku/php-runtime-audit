<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Evidence;

use PHPUnit\Framework\TestCase;
use InvalidArgumentException;
use voku\PhpRuntimeAudit\Evidence\Assessment;
use voku\PhpRuntimeAudit\Evidence\AssessmentVerdict;
use voku\PhpRuntimeAudit\Evidence\ApplicabilityRecord;
use voku\PhpRuntimeAudit\Evidence\CompromiseStatus;
use voku\PhpRuntimeAudit\Evidence\Coverage;
use voku\PhpRuntimeAudit\Evidence\EvidenceModelFactory;
use voku\PhpRuntimeAudit\Evidence\EvidenceValidator;
use voku\PhpRuntimeAudit\Evidence\Finding;
use voku\PhpRuntimeAudit\Evidence\Freshness;
use voku\PhpRuntimeAudit\Evidence\Observation;
use voku\PhpRuntimeAudit\Evidence\ObservationFact;
use voku\PhpRuntimeAudit\Evidence\PatchStatus;

final class EvidenceValidatorTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../fixtures/evidence/v1';

    public function test_valid_fixtures_round_trip_through_schemas_and_typed_models(): void
    {
        $validator = new EvidenceValidator();

        foreach ([
            'observation.valid.json' => Observation::class,
            'applicability.valid.json' => ApplicabilityRecord::class,
            'assessment.valid.json' => Assessment::class,
            'assessment.needs-investigation.valid.json' => Assessment::class,
            'assessment.potentially-affected.valid.json' => Assessment::class,
            'assessment.unknown.valid.json' => Assessment::class,
            'coverage.valid.json' => Coverage::class,
            'finding.valid.json' => Finding::class,
        ] as $fixture => $expectedClass) {
            $result = $validator->validate($this->fixture($fixture));

            self::assertTrue($result->valid, $fixture . ': ' . implode('; ', $result->errors));
            self::assertInstanceOf($expectedClass, $result->record);
            self::assertSame([], $result->errors);
            self::assertSame('1.0', $result->schemaVersion);

            $roundTrip = json_encode($result->record->toArray(), JSON_THROW_ON_ERROR);
            $roundTripResult = $validator->validate($roundTrip);
            self::assertTrue($roundTripResult->valid, $fixture . ' model round trip failed.');
            self::assertSame($result->record->recordType(), $roundTripResult->record?->recordType());
        }
    }

    public function test_source_freshness_is_derived_only_from_caller_supplied_digests(): void
    {
        $validator = new EvidenceValidator();
        $cases = [
            'observation.valid.json' => Freshness::Fresh,
            'observation.stale.json' => Freshness::Stale,
            'observation.unknown-freshness.json' => Freshness::Unknown,
        ];

        foreach ($cases as $fixture => $expected) {
            $result = $validator->validate($this->fixture($fixture));
            self::assertTrue($result->valid, implode('; ', $result->errors));
            self::assertInstanceOf(Observation::class, $result->record);
            self::assertSame($expected, $result->record->sources[0]->freshness);
        }
    }

    public function test_unavailable_current_digest_stays_unknown_and_never_becomes_fresh(): void
    {
        $data = $this->fixtureData('observation.valid.json');
        self::assertIsArray($data['sources']);
        self::assertIsArray($data['sources'][0]);
        $data['sources'][0]['current_digest'] = null;
        $data['sources'][0]['freshness'] = 'unknown';

        $result = (new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR));
        self::assertTrue($result->valid, implode('; ', $result->errors));
        self::assertInstanceOf(Observation::class, $result->record);
        self::assertSame(Freshness::Unknown, $result->record->sources[0]->freshness);
    }

    public function test_freshness_claim_that_conflicts_with_digests_is_rejected(): void
    {
        $json = str_replace('"freshness": "fresh"', '"freshness": "stale"', $this->fixture('observation.valid.json'));
        $result = (new EvidenceValidator())->validate($json);

        self::assertFalse($result->valid);
        self::assertStringContainsString('freshness', implode('; ', $result->errors));
    }

    public function test_fact_provenance_must_resolve_to_a_declared_source(): void
    {
        $data = $this->fixtureData('observation.valid.json');
        self::assertIsArray($data['facts']);
        self::assertIsArray($data['facts'][0]);
        $data['facts'][0]['source_id'] = 'source.not-present';
        $result = (new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR));

        self::assertFalse($result->valid);
        self::assertStringContainsString('missing source_id', implode('; ', $result->errors));
    }

    public function test_model_factory_does_not_skip_schema_validation(): void
    {
        $data = $this->fixtureData('observation.valid.json');
        self::assertIsArray($data['facts']);
        self::assertIsArray($data['facts'][0]);
        unset($data['facts'][0]['value']);

        $this->expectException(InvalidArgumentException::class);
        EvidenceModelFactory::fromArray($data);
    }

    public function test_observation_fact_parser_rejects_a_missing_nullable_value(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ObservationFact::fromArray([
            'fact_id' => 'fact.missing-value',
            'key' => 'runtime.value',
            'source_id' => 'source.runtime',
        ]);
    }

    public function test_empty_json_object_fact_values_survive_the_typed_model_round_trip(): void
    {
        $json = str_replace('"value": "8.3.12"', '"value": {}', $this->fixture('observation.valid.json'));
        $result = (new EvidenceValidator())->validate($json);

        self::assertTrue($result->valid, implode('; ', $result->errors));
        self::assertInstanceOf(Observation::class, $result->record);
        $roundTrip = json_encode($result->record->toArray(), JSON_THROW_ON_ERROR);
        $decoded = json_decode($roundTrip, false, 64, JSON_THROW_ON_ERROR);
        self::assertInstanceOf(\stdClass::class, $decoded);
        self::assertIsArray($decoded->facts);
        self::assertInstanceOf(\stdClass::class, $decoded->facts[0]);
        self::assertInstanceOf(\stdClass::class, $decoded->facts[0]->value);
        self::assertSame([], get_object_vars($decoded->facts[0]->value));
    }

    public function test_schema_and_evidence_cli_changes_are_in_the_pull_request_ci_path_filter(): void
    {
        $workflow = file_get_contents(dirname(__DIR__, 2) . '/.github/workflows/bootstrap.yml');
        self::assertIsString($workflow);
        self::assertStringContainsString("'resources/schemas/**'", $workflow);
        self::assertStringContainsString("'bin/php-runtime-audit-evidence'", $workflow);
    }

    public function test_unsupported_record_types_and_schema_versions_fail_closed(): void
    {
        $validator = new EvidenceValidator();
        foreach (['observation.unknown-version.json', 'assessment.unsupported-verdict.json'] as $fixture) {
            self::assertFalse($validator->validate($this->fixture($fixture))->valid, $fixture);
        }

        $data = $this->fixtureData('observation.valid.json');
        $data['record_type'] = 'future_record';
        self::assertFalse($validator->validate(json_encode($data, JSON_THROW_ON_ERROR))->valid);
    }

    public function test_missing_hostile_and_duplicate_fields_are_rejected(): void
    {
        $validator = new EvidenceValidator();
        foreach ([
            'observation.hostile-property.json',
            'observation.duplicate-key.json',
            'applicability.missing-field.json',
            'finding.missing-independent-verification.json',
            'assessment.conflicting-verdict.json',
        ] as $fixture) {
            $result = $validator->validate($this->fixture($fixture));
            self::assertFalse($result->valid, $fixture);
            self::assertNotEmpty($result->errors, $fixture);
        }

        $escapedDuplicateKey = '{"record_type":"observation","\\u0072ecord_type":"observation"}';
        $escapedResult = $validator->validate($escapedDuplicateKey);
        self::assertFalse($escapedResult->valid);
        self::assertStringContainsString('duplicate', strtolower(implode('; ', $escapedResult->errors)));
    }

    public function test_malformed_and_non_object_json_are_rejected(): void
    {
        $validator = new EvidenceValidator();
        foreach (['{"record_type":', '[]', 'null', '{"a":1,}'] as $json) {
            self::assertFalse($validator->validate($json)->valid, $json);
        }
    }

    public function test_oversized_input_is_rejected_before_schema_parsing(): void
    {
        $result = (new EvidenceValidator())->validate(str_repeat(' ', EvidenceValidator::MAX_INPUT_BYTES + 1));

        self::assertFalse($result->valid);
        self::assertStringContainsString('1 MiB', implode('; ', $result->errors));
    }

    public function test_assessment_keeps_patch_and_compromise_evidence_separate(): void
    {
        $result = (new EvidenceValidator())->validate($this->fixture('assessment.needs-investigation.valid.json'));

        self::assertTrue($result->valid, implode('; ', $result->errors));
        self::assertInstanceOf(Assessment::class, $result->record);
        self::assertSame(PatchStatus::VerifiedFixed, $result->record->patchStatus);
        self::assertSame(AssessmentVerdict::NeedsInvestigation, $result->record->verdict);
        self::assertSame(CompromiseStatus::Confirmed, $result->record->compromiseEvidence->status);
        self::assertNotSame($result->record->patchEvidenceIds, $result->record->compromiseEvidence->evidenceIds);
    }

    public function test_unknown_assessment_verdict_remains_unknown(): void
    {
        $result = (new EvidenceValidator())->validate($this->fixture('assessment.unknown.valid.json'));

        self::assertTrue($result->valid, implode('; ', $result->errors));
        self::assertInstanceOf(Assessment::class, $result->record);
        self::assertSame(AssessmentVerdict::Unknown, $result->record->verdict);
        self::assertSame(PatchStatus::Unknown, $result->record->patchStatus);
        self::assertSame(CompromiseStatus::Unknown, $result->record->compromiseEvidence->status);
    }

    public function test_verified_fixed_patch_status_requires_evidence_with_any_overall_verdict(): void
    {
        $result = (new EvidenceValidator())->validate($this->fixture('assessment.investigation-without-patch-evidence.json'));

        self::assertFalse($result->valid);
        self::assertStringContainsString('patch_evidence_ids', implode('; ', $result->errors));
    }

    public function test_potentially_affected_patch_status_requires_evidence(): void
    {
        $result = (new EvidenceValidator())->validate($this->fixture('assessment.potentially-affected.without-patch-evidence.json'));

        self::assertFalse($result->valid);
        self::assertStringContainsString('patch_evidence_ids', implode('; ', $result->errors));
    }

    public function test_assessment_model_rejects_potentially_affected_status_without_evidence(): void
    {
        $data = $this->fixtureData('assessment.potentially-affected.without-patch-evidence.json');

        try {
            Assessment::fromArray($data);
            self::fail('The model accepted a positive patch status without evidence.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('patch evidence', $exception->getMessage());
        }
    }

    public function test_material_confirmed_findings_need_independent_verification_evidence(): void
    {
        $data = $this->fixtureData('finding.valid.json');
        $data['independent_verification'] = null;
        $result = (new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR));

        self::assertFalse($result->valid);
        self::assertStringContainsString('independent_verification', implode('; ', $result->errors));
    }

    public function test_independent_verification_must_cite_distinct_evidence(): void
    {
        $data = $this->fixtureData('finding.valid.json');
        self::assertIsArray($data['independent_verification']);
        $data['independent_verification']['evidence_ids'] = $data['evidence_ids'];
        $result = (new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR));

        self::assertFalse($result->valid);
        self::assertStringContainsString('distinct from the finding evidence', implode('; ', $result->errors));
    }

    public function test_malformed_calendar_timestamps_are_rejected(): void
    {
        $data = $this->fixtureData('applicability.valid.json');
        $data['assessed_at'] = '2026-02-30T12:10:00Z';
        self::assertFalse((new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR))->valid);
    }

    public function test_duplicate_coverage_subject_check_pairs_are_rejected(): void
    {
        $data = $this->fixtureData('coverage.valid.json');
        self::assertIsArray($data['entries']);
        self::assertIsArray($data['entries'][0]);
        self::assertIsArray($data['entries'][1]);
        $data['entries'][1]['subject_id'] = $data['entries'][0]['subject_id'];
        $data['entries'][1]['check_id'] = $data['entries'][0]['check_id'];
        $result = (new EvidenceValidator())->validate(json_encode($data, JSON_THROW_ON_ERROR));

        self::assertFalse($result->valid);
        self::assertStringContainsString('duplicate subject_id/check_id', implode('; ', $result->errors));
    }

    public function test_unknown_applicability_requires_a_reason_and_known_state_requires_evidence(): void
    {
        $validator = new EvidenceValidator();
        $unknown = $this->fixtureData('applicability.unknown.valid.json');
        $unknown['reason'] = null;
        self::assertFalse($validator->validate(json_encode($unknown, JSON_THROW_ON_ERROR))->valid);

        $known = $this->fixtureData('applicability.valid.json');
        $known['evidence_ids'] = [];
        self::assertFalse($validator->validate(json_encode($known, JSON_THROW_ON_ERROR))->valid);
    }

    public function test_cli_validates_the_supplied_local_file_without_modifying_it(): void
    {
        $fixture = realpath(self::FIXTURES . '/observation.valid.json');
        self::assertIsString($fixture);
        $before = hash_file('sha256', $fixture);
        $cli = dirname(__DIR__, 2) . '/bin/php-runtime-audit-evidence';
        $process = proc_open(
            [PHP_BINARY, $cli, 'validate', $fixture],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame('', $stderr);
        self::assertSame(0, $exitCode);
        $result = $this->decodeObject((string) $stdout);
        self::assertSame(true, $result['valid']);
        self::assertSame($before, hash_file('sha256', $fixture));
    }

    public function test_cli_rejects_stream_wrappers_before_opening_them(): void
    {
        $cli = dirname(__DIR__, 2) . '/bin/php-runtime-audit-evidence';
        $process = proc_open(
            [PHP_BINARY, $cli, 'validate', 'https://127.0.0.1/should-never-be-requested'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame('', $stderr);
        self::assertSame(2, $exitCode);
        $result = $this->decodeObject((string) $stdout);
        self::assertFalse($result['valid']);
        self::assertIsArray($result['errors']);
        self::assertIsString($result['errors'][0]);
        self::assertStringContainsString('stream wrappers', $result['errors'][0]);
    }

    public function test_cli_rejects_unc_network_paths_before_opening_them(): void
    {
        $cli = dirname(__DIR__, 2) . '/bin/php-runtime-audit-evidence';
        $unc = chr(92) . chr(92) . 'audit-server' . chr(92) . 'share' . chr(92) . 'evidence.json';
        $process = proc_open(
            [PHP_BINARY, $cli, 'validate', $unc],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame('', $stderr);
        self::assertSame(2, $exitCode);
        $result = $this->decodeObject((string) $stdout);
        self::assertFalse($result['valid']);
        self::assertIsArray($result['errors']);
        self::assertIsString($result['errors'][0]);
        self::assertStringContainsString('network paths', $result['errors'][0]);
    }

    public function test_cli_handles_register_argc_argv_disabled(): void
    {
        $cli = dirname(__DIR__, 2) . '/bin/php-runtime-audit-evidence';
        $process = proc_open(
            [PHP_BINARY, '-d', 'register_argc_argv=0', $cli],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
            dirname(__DIR__, 2),
        );
        self::assertIsResource($process);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        self::assertSame('', $stderr);
        self::assertSame(2, $exitCode);
        $result = $this->decodeObject((string) $stdout);
        self::assertFalse($result['valid']);
        self::assertSame(['Usage: php bin/php-runtime-audit-evidence validate <local-json-file>'], $result['errors']);
    }

    /** @return array<string, mixed> */
    private function fixtureData(string $name): array
    {
        return $this->decodeObject($this->fixture($name));
    }

    /** @return array<string, mixed> */
    private function decodeObject(string $json): array
    {
        $decoded = json_decode($json, true, 64, JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        $object = [];
        foreach ($decoded as $key => $value) {
            self::assertIsString($key);
            $object[$key] = $value;
        }
        return $object;
    }

    private function fixture(string $name): string
    {
        $contents = file_get_contents(self::FIXTURES . '/' . $name);
        self::assertIsString($contents);
        return $contents;
    }
}
