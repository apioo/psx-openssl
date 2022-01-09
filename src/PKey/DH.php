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
 * DH
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class DH extends TypeAbstract
{
    /**
     * @var string
     */
    private $p;

    /**
     * @var string
     */
    private $g;

    /**
     * @var string
     */
    private $privKey;

    /**
     * @var string
     */
    private $pubKey;

    /**
     * @param string $p
     * @param string $g
     * @param string $privKey
     * @param string $pubKey
     */
    public function __construct(int $bits, string $key, string $p, string $g, string $privKey, string $pubKey)
    {
        parent::__construct($bits, $key);

        $this->p = $p;
        $this->g = $g;
        $this->privKey = $privKey;
        $this->pubKey = $pubKey;
    }

    /**
     * @return string
     */
    public function getP(): string
    {
        return $this->p;
    }

    /**
     * @return string
     */
    public function getG(): string
    {
        return $this->g;
    }

    /**
     * @return string
     */
    public function getPrivKey(): string
    {
        return $this->privKey;
    }

    /**
     * @return string
     */
    public function getPubKey(): string
    {
        return $this->pubKey;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? 0,
            $details['key'] ?? '',
            $details['dh']['p'] ?? '',
            $details['dh']['g'] ?? '',
            $details['dh']['priv_key'] ?? '',
            $details['dh']['pub_key'] ?? '',
        );
    }
}
