<?php

    namespace FederationAdGuard\Exceptions;

    use Exception;

    /**
     * Thrown when a filter list or the FilterLists directory cannot be used, e.g., a URL is not permitted,
     * unreachable or responded with an error, a local file is not readable, a list is too large or the FilterLists
     * API responded with something it doesn't document. When a server responded with an error, the code is its HTTP
     * status.
     */
    class ListException extends Exception
    {
    }
