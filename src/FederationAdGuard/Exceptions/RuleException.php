<?php

    namespace FederationAdGuard\Exceptions;

    use Exception;

    /**
     * Thrown when a filter rule cannot be used, e.g., a custom rule with a syntax error or a modifier that is not
     * supported. The message explains why.
     */
    class RuleException extends Exception
    {
    }
