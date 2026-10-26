<?php

declare(strict_types=1);

namespace voku\PhpRuntimeAudit\Tests\Evidence;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use stdClass;
use voku\PhpRuntimeAudit\Evidence\RecordData;

final class RecordDataTest extends TestCase
{
    public function test_object_conversion_preserves_string_properties_and_nested_object_values(): void
    {
        $nested = new stdClass();
        $object = (object) ['value' => $nested];

        self::assertSame(['value' => $nested], RecordData::object($object, 'record'));
        self::assertSame(['value' => $nested], RecordData::object(['value' => $nested], 'record'));
        self::assertSame([], RecordData::object(new stdClass(), 'record'));
    }

    public function test_object_conversion_rejects_integer_keys_instead_of_claiming_string_keyed_output(): void
    {
        $object = json_decode('{"0":"value"}', false, 64, JSON_THROW_ON_ERROR);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('string property names');
        RecordData::object($object, 'record');
    }

    public function test_object_conversion_rejects_list_arrays(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RecordData::object(['value'], 'record');
    }
}
