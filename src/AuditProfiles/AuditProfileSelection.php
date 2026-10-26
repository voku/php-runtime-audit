<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\AuditProfiles;

final readonly class AuditProfileSelection
{
    /**
     * @param list<SelectedProfile> $profiles
     * @param list<string> $unknownInputs
     */
    public function __construct(
        public AuditIntent $intent,
        private array $profiles,
        private array $unknownInputs,
    ) {}

    /** @return list<string> */
    public function profileIds(): array
    {
        return array_map(
            static fn(SelectedProfile $profile): string => $profile->id,
            $this->profiles,
        );
    }

    /** @return list<string> */
    public function unknownInputs(): array
    {
        return $this->unknownInputs;
    }

    /** @return array{intent: string, profiles: list<array{id: string, reason: string}>, unknown_inputs: list<string>} */
    public function toArray(): array
    {
        return [
            'intent' => $this->intent->value,
            'profiles' => array_map(
                static fn(SelectedProfile $profile): array => $profile->toArray(),
                $this->profiles,
            ),
            'unknown_inputs' => $this->unknownInputs,
        ];
    }
}
