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
 * RSA
 *
 * @author  Christoph Kappestein <christoph.kappestein@gmail.com>
 * @license http://www.apache.org/licenses/LICENSE-2.0
 * @link    https://phpsx.org
 */
class RSA extends TypeAbstract
{
    private string $n;
    private string $e;
    private string $d;
    private string $p;
    private string $q;
    private string $dmp1;
    private string $dmq1;
    private string $iqmp;

    public function __construct(int $bits, string $key, string $n, string $e, string $d, string $p, string $q, string $dmp1, string $dmq1, string $iqmp)
    {
        parent::__construct($bits, $key);
        
        $this->n = $n;
        $this->e = $e;
        $this->d = $d;
        $this->p = $p;
        $this->q = $q;
        $this->dmp1 = $dmp1;
        $this->dmq1 = $dmq1;
        $this->iqmp = $iqmp;
    }

    public function getN(): string
    {
        return $this->n;
    }

    public function getE(): string
    {
        return $this->e;
    }

    public function getD(): string
    {
        return $this->d;
    }

    public function getP(): string
    {
        return $this->p;
    }

    public function getQ(): string
    {
        return $this->q;
    }

    public function getDmp1(): string
    {
        return $this->dmp1;
    }

    public function getDmq1(): string
    {
        return $this->dmq1;
    }

    public function getIqmp(): string
    {
        return $this->iqmp;
    }

    public static function fromArray(array $details): self
    {
        return new self(
            $details['bits'] ?? 0,
            $details['key'] ?? '',
            $details['rsa']['n'] ?? '',
            $details['rsa']['e'] ?? '',
            $details['rsa']['d'] ?? '',
            $details['rsa']['p'] ?? '',
            $details['rsa']['q'] ?? '',
            $details['rsa']['dmp1'] ?? '',
            $details['rsa']['dmq1'] ?? '',
            $details['rsa']['iqmp'] ?? '',
        );
    }
}
