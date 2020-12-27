<?php
/*
 * PSX is a open source PHP framework to develop RESTful APIs.
 * For the current version and informations visit <http://phpsx.org>
 *
 * Copyright 2010-2016 Christoph Kappestein <k42b3.x@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace PSX\OpenSsl;

use InvalidArgumentException;

/**
 * PKey
 *
 * @author  Christoph Kappestein <k42b3.x@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    http://phpsx.org
 */
class PKey
{
    use ErrorHandleTrait;

    /**
     * @var resource
     */
    private $res;

    /**
     * @param array $configargs
     */
    public function __construct($configargs = [])
    {
        if (is_array($configargs)) {
            $res = openssl_pkey_new($configargs);

            self::handleReturn($res);

            $this->res = $res;
        } elseif (is_resource($configargs) || is_object($configargs)) {
            $this->res = $configargs;
        } else {
            throw new InvalidArgumentException('Must be either an array or a resource, got ' . gettype($configargs));
        }
    }

    /**
     * @deprecated
     */
    public function free(): void
    {
        if (PHP_MAJOR_VERSION >= 8) {
            // deprecated in PHP 8
            return;
        }

        openssl_pkey_free($this->res);
    }

    /**
     * @return PKey\TypeAbstract
     * @throws Exception
     */
    public function getDetails(): PKey\TypeAbstract
    {
        $details = openssl_pkey_get_details($this->res);

        self::handleReturn($details);

        $type = $details['type'] ?? null;
        if ($type === OPENSSL_KEYTYPE_RSA) {
            return PKey\RSA::fromArray($details);
        } elseif ($type === OPENSSL_KEYTYPE_DSA) {
            return PKey\DSA::fromArray($details);
        } elseif ($type === OPENSSL_KEYTYPE_DH) {
            return PKey\DH::fromArray($details);
        } elseif ($type === OPENSSL_KEYTYPE_EC) {
            return PKey\EC::fromArray($details);
        } else {
            throw new Exception('Unknown key type');
        }
    }

    /**
     * @return string
     * @throws Exception
     */
    public function getPublicKey(): string
    {
        return $this->getDetails()->getKey();
    }

    /**
     * @internal 
     * @return resource
     */
    public function getResource()
    {
        return $this->res;
    }

    /**
     * @param string|null $out
     * @param string|null $passphrase
     * @param array $configargs
     * @return bool
     */
    public function export(?string &$out, ?string $passphrase = null, array $configargs = array()): bool
    {
        return self::handleReturn(openssl_pkey_export($this->res, $out, $passphrase, $configargs));
    }

    /**
     * @param string $key
     * @param string|null $passphrase
     * @return PKey
     */
    public static function getPrivate(string $key, ?string $passphrase = null): self
    {
        return new self(self::handleReturn(openssl_pkey_get_private($key, $passphrase)));
    }

    /**
     * @param string|resource $certificate
     * @return PKey
     */
    public static function getPublic($certificate): self
    {
        return new self(self::handleReturn(openssl_pkey_get_public($certificate)));
    }
}
