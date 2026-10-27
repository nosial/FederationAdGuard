<?php

    namespace FederationAdGuard\Classes;

    use FederationAdGuard\Objects\SubscriptionDefinition;
    use FederationAdGuard\Exceptions\ListException;

    class LocalLists
    {
        /**
         * Expands a local path into the list files it declares.
         *
         * @param SubscriptionDefinition $definition A local file or directory and its settings
         * @return SubscriptionDefinition[] The files
         * @throws ListException If the path cannot be read
         */
        public static function expand(SubscriptionDefinition $definition): array
        {
            $path = $definition->getLocation();
            clearstatcache(true, $path);
            if(!is_readable($path))
            {
                throw new ListException(sprintf('The filter list path %s is not readable', $path));
            }

            if(is_file($path))
            {
                return [$definition];
            }

            if(!is_dir($path) || ($entries = @scandir($path)) === false)
            {
                throw new ListException(sprintf('The filter list path %s is not a readable file or directory', $path));
            }

            $files = [];
            foreach($entries as $entry)
            {
                if(str_starts_with($entry, '.'))
                {
                    continue;
                }

                $file = $path . DIRECTORY_SEPARATOR . $entry;
                if(is_link($file) && !file_exists($file))
                {
                    throw new ListException(sprintf('The filter list link %s has no readable target', $file));
                }

                if(is_file($file))
                {
                    if(!is_readable($file))
                    {
                        throw new ListException(sprintf('The filter list file %s is not readable', $file));
                    }

                    $files[] = $definition->withFile($file);
                }
            }

            return $files;
        }

        /**
         * Reads a filter list with the same size limit used for downloaded lists.
         *
         * @param string $path The local file
         * @param int $maxSize The maximum number of bytes
         * @return string The contents
         * @throws ListException If the file cannot be read or exceeds the limit
         */
        public static function read(string $path, int $maxSize): string
        {
            if(!is_file($path) || !is_readable($path))
            {
                throw new ListException(sprintf('The filter list file %s is not readable', $path));
            }

            $contents = @file_get_contents($path, false, null, 0, $maxSize + 1);
            if($contents === false)
            {
                throw new ListException(sprintf('The filter list file %s could not be read', $path));
            }

            if(strlen($contents) > $maxSize)
            {
                throw new ListException(sprintf('The filter list file %s exceeds the maximum size of %d bytes', $path, $maxSize));
            }

            return $contents;
        }
    }
