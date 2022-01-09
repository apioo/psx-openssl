<?php
/*
 * PSX is an open source PHP framework to develop RESTful APIs.
 * For the current version and information visit <https://phpsx.org>
 *
 * Copyright 2010-2022 Christoph Kappestein <christoph.kappestein@gmail.com>
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

namespace PSX\OpenSsl\PKey;

/**
 * DSA
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class DSA extends TypeAbstract
{
    private string $p;
    private string $q;
    private string $g;
    private string $privKey;
    private string $pubKey;

    public function __construct(int $bits, string $key, string $p, string $q, string $g, string $privKey, string $pubKey)
    {
        parent::__construct($bits, $key);
        
        $this->p = $p;
        $this->q = $q;
        $this->g = $g;
        $this->privKey = $privKey;
        $this->pubKey = $pubKey;
    }

    public function getP(): string
    {
        return $this->p;
    }

    public function getQ(): string
    {
        return $this->q;
    }

    public function getG(): string
    {
        return $this->g;
    }

    public function getPrivKey(): string
    {
        return $this->privKey;
    }

    public function getPubKey(): string
    {
        return $this->pubKey;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? 0,
            $details['key'] ?? '',
            $details['rsa']['p'] ?? '',
            $details['rsa']['q'] ?? '',
            $details['rsa']['g'] ?? '',
            $details['rsa']['priv_key'] ?? '',
            $details['rsa']['pub_key'] ?? '',
        );
    }
}
