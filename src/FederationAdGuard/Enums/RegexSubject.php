<?php

    namespace FederationAdGuard\Enums;

    enum RegexSubject : string
    {
        /**
         * The full URL, e.g., Adblock Plus /^https?:\/\/[a-z]{8}\.top\// rules. Never evaluated for a bare DNS name.
         */
        case URL = 'URL';

        /**
         * The DNS name, e.g., Pi-hole's (^|\.)example\.com$ rules. Evaluated for DNS names and for the host of URLs.
         */
        case HOST = 'HOST';
    }
