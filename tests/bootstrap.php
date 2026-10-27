<?php

    require 'ncc';

    // Resolve the dependency here so direct PHPUnit and IDE runs use the same build as make test.
    $federationBuildOutputPath = getenv('FEDERATIONLIB_BUILD_OUTPUT_PATH');
    if(!$federationBuildOutputPath)
    {
        $localFederationBuildOutputPath = __DIR__ . '/../../FederationLib/target/release/net.nosial.federation.ncc';
        $federationBuildOutputPath = is_file($localFederationBuildOutputPath)
            ? $localFederationBuildOutputPath
            : 'net.nosial.federation';
    }

    import($federationBuildOutputPath);
    if(!defined('FederationLib\\Enums\\EventType::STARTUP') || !defined('FederationLib\\Enums\\EventType::MAINTENANCE'))
    {
        throw new RuntimeException('FederationAdGuard requires FederationLib with lifecycle events. Set FEDERATIONLIB_BUILD_OUTPUT_PATH to a current FederationLib build.');
    }

    $buildOutputPath = getenv('NCC_BUILD_OUTPUT_PATH') ?: __DIR__ . '/../target/release/net.nosial.federation_adguard.ncc';
    if(!file_exists($buildOutputPath))
    {
        throw new Exception('Build output not found: ' . $buildOutputPath);
    }

    import($buildOutputPath);

    // Keep the tests' configuration separate from any server installed on this machine.
    if(!getenv('CONFIGLIB_PATH'))
    {
        putenv('CONFIGLIB_PATH=' . __DIR__ . '/../target/tests/configlib');
    }

    foreach(glob(__DIR__ . '/FederationAdGuard/Helpers/*.php') as $helper)
    {
        require_once $helper;
    }

    \LogLib2\Logger::unregisterHandlers();
