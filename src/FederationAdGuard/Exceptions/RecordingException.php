<?php

    namespace FederationAdGuard\Exceptions;

    use Exception;

    /**
     * Thrown when the plugin cannot write its records to FederationLib's database because of the FederationAdGuard
     * operator they are attributed to, e.g., it doesn't exist, is disabled or is being provisioned by another process
     */
    class RecordingException extends Exception
    {
    }
