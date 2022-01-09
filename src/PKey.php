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
use PSX\OpenSsl\Exception\OpenSslException;

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

    private \OpenSSLAsymmetricKey $key;

    /**
     * @throws OpenSslException
     */
    public function __construct(array|\OpenSSLAsymmetricKey $options = [])
    {
        if (is_array($options)) {
            $key = openssl_pkey_new($options);

            self::throwExceptionOnFalse($key);

            $this->key = $key;
        } else {
            $this->key = $options;
        }
    }

    /**
     * @return PKey\TypeAbstract
     * @throws OpenSslException
     */
    public function getDetails(): PKey\TypeAbstract
    {
        $details = openssl_pkey_get_details($this->key);

        self::throwExceptionOnFalse($details);

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
            throw new OpenSslException('Unknown key type');
        }
    }

    /**
     * @throws OpenSslException
     */
    public function getPublicKey(): string
    {
        return $this->getDetails()->getKey();
    }

    /**
     * @internal 
     */
    public function getResource(): \OpenSSLAsymmetricKey
    {
        return $this->key;
    }

    /**
     * @throws OpenSslException
     */
    public function export(?string &$out, ?string $passphrase = null, array $configargs = array()): bool
    {
        return self::throwExceptionOnFalse(openssl_pkey_export($this->key, $out, $passphrase, $configargs));
    }

    /**
     * @throws OpenSslException
     */
    public static function getPrivate(string $key, ?string $passphrase = null): self
    {
        return new self(self::throwExceptionOnFalse(openssl_pkey_get_private($key, $passphrase)));
    }

    /**
     * @throws OpenSslException
     */
    public static function getPublic(mixed $certificate): self
    {
        return new self(self::throwExceptionOnFalse(openssl_pkey_get_public($certificate)));
    }
}
