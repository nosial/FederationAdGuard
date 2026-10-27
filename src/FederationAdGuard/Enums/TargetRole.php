<?php

    namespace FederationAdGuard\Enums;

    enum TargetRole : string
    {
        /**
         * The content is about the name or URL itself: a HOSTNAME, a URL, or the page a WEB_PAGE declares
         */
        case SUBJECT = 'SUBJECT';

        /**
         * The name or URL is mentioned in the text of the content, e.g., a link in a message
         */
        case LINK = 'LINK';
    }
