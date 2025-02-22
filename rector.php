<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use Rector\Core\ValueObject\PhpVersion;
use Rector\Doctrine\Set\DoctrineSetList;
use Rector\Php74\Rector\Property\TypedPropertyRector;
use Rector\PHPUnit\Set\PHPUnitLevelSetList;
use Rector\PHPUnit\Set\PHPUnitSetList;
use Rector\Set\ValueObject\LevelSetList;
use Rector\Set\ValueObject\SetList;
use Rector\Symfony\Set\SymfonyLevelSetList;
use Rector\Symfony\Set\SymfonySetList;

return static function (RectorConfig $config): void {
    $config->sets([
        SetList::DEAD_CODE,
        LevelSetList::UP_TO_PHP_81,
        SymfonyLevelSetList::UP_TO_SYMFONY_54,
        SymfonySetList::SYMFONY_CODE_QUALITY,
        SymfonySetList::SYMFONY_CONSTRUCTOR_INJECTION,
        SymfonySetList::SYMFONY_STRICT,
        DoctrineSetList::DOCTRINE_CODE_QUALITY,
        DoctrineSetList::ANNOTATIONS_TO_ATTRIBUTES,
        PHPUnitSetList::PHPUNIT_SPECIFIC_METHOD,
        PHPUnitLevelSetList::UP_TO_PHPUNIT_100,
        PHPUnitSetList::PHPUNIT_CODE_QUALITY,
        PHPUnitSetList::PHPUNIT_EXCEPTION,
        PHPUnitSetList::REMOVE_MOCKS,
        PHPUnitSetList::PHPUNIT_YIELD_DATA_PROVIDER,
    ]);
    $config->parallel();
    $config->paths([__DIR__ . '/src', __DIR__ . '/performance', __DIR__ . '/tests']);
    $config->skip([
        __DIR__ . '/src/Component/Core/JWKSet.php',
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSource.php',
        __DIR__ . '/src/Bundle/JoseFramework/DependencyInjection/Source/KeyManagement/JWKSetSource.php',
    ]);
    $config->phpVersion(PhpVersion::PHP_81);
    $config->importNames();
    $config->importShortClasses();

    $services = $config->services();
    $services->set(TypedPropertyRector::class);
};
