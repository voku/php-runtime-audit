<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Evidence;

enum RecordType: string
{
    case Observation = 'observation';
    case Applicability = 'applicability';
    case Assessment = 'assessment';
    case Coverage = 'coverage';
    case Finding = 'finding';

    public function schemaFile(): string
    {
        return $this->value . '.schema.json';
    }
}
