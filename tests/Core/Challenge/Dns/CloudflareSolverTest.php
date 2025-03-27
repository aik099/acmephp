<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tests\AcmePhp\Core\Challenge\Dns;

use AcmePhp\Core\Challenge\Dns\CloudflareSolver;
use AcmePhp\Core\Challenge\Dns\DnsDataExtractor;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use GuzzleHttp\ClientInterface;
use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\ObjectProphecy;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

class CloudflareSolverTest extends TestCase
{
    use ProphecyTrait;

    /**
     * @var DnsDataExtractor|ObjectProphecy
     */
    protected $mockExtractor;

    /**
     * @var ClientInterface|ObjectProphecy
     */
    protected $mockClient;

    /**
     * @var CloudflareSolver
     */
    protected $solver;

    protected function setUp(): void
    {
        parent::setUp();

        $this->mockExtractor = $this->prophesize(DnsDataExtractor::class);
        $this->mockClient = $this->prophesize(ClientInterface::class);

        $this->solver = new CloudflareSolver($this->mockExtractor->reveal(), $this->mockClient->reveal());
        $this->solver->configure(['api_key' => 'stub_api_key']);
    }

    public function testSupports()
    {
        $typeDns = 'dns-01';
        $typeHttp = 'http-01';

        $stubChallenge = $this->prophesize(AuthorizationChallenge::class);

        $stubChallenge->getType()->willReturn($typeDns);
        $this->assertTrue($this->solver->supports($stubChallenge->reveal()));

        $stubChallenge->getType()->willReturn($typeHttp);
        $this->assertFalse($this->solver->supports($stubChallenge->reveal()));
    }

    public function testSolve()
    {
        $testData = $this->getTestData(true);
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsAddition($zoneId, $zoneData['zoneName'], $zoneData['domains']);
        }

        $this->solver->solve(reset($challenges));
    }

    public function testSolveAll()
    {
        $testData = $this->getTestData();
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsAddition($zoneId, $zoneData['zoneName'], $zoneData['domains']);
        }

        $this->solver->solveAll($challenges);
    }

    protected function getResponseMock($response)
    {
        $stream = $this->prophesize(StreamInterface::class);
        $stream->getContents()->willReturn($response);

        $response = $this->prophesize(ResponseInterface::class);
        $response->getBody()->willReturn($stream->reveal());

        return $response->reveal();
    }

    public function testCleanupWithoutPreviousDnsRecords()
    {
        $testData = $this->getTestData(true);
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsQuery($zoneId, $zoneData['zoneName'], []);
        }

        $this->solver->cleanup(reset($challenges));
    }

    public function testCleanupWithPreviousDnsRecords()
    {
        $testData = $this->getTestData(true);
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsQuery($zoneId, $zoneData['zoneName'], $zoneData['domains']);
            $this->expectDnsRecordsDeletion($zoneId, $zoneData['zoneName'], $zoneData['domains']);
        }

        $this->solver->cleanup(reset($challenges));
    }

    public function testCleanupAllWithoutPreviousDnsRecords()
    {
        $testData = $this->getTestData();
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsQuery($zoneId, $zoneData['zoneName'], []);
        }

        $this->solver->cleanupAll($challenges);
    }

    public function testCleanupAllWithPreviousDnsRecords()
    {
        $testData = $this->getTestData();
        $challenges = $this->createChallengeMocks($testData);
        $this->expectZonesQuery($testData);

        foreach ($testData as $zoneId => $zoneData) {
            $this->expectDnsRecordsQuery($zoneId, $zoneData['zoneName'], $zoneData['domains']);
            $this->expectDnsRecordsDeletion($zoneId, $zoneData['zoneName'], $zoneData['domains']);
        }

        $this->solver->cleanupAll($challenges);
    }

    protected function getTestData($singleRecord = false)
    {
        if ($singleRecord) {
            // The "recordId" keys were populated using this code: md5(uniqid('', true)).
            return [
                /* key - zoneId */
                '167a0418dd8ce3bf0ef00dfb6195f038' => [
                    'zoneName' => 'foo.com',
                    'domains' => [
                        [
                            'recordId' => '4536b661a67872e2026182eb5d55c6bd',
                            'domain' => 'sub-domain.foo.com',
                            'recordName' => '_acme-challenge.sub-domain.foo.com.',
                            'recordValue' => 'record_value',
                        ],
                    ],
                ],
            ];
        }

        // The "recordId" keys were populated using this code: md5(uniqid('', true)).
        return [
            /* key - zoneId */
            '0ab6a5f3c2d412a1084ae502b34fb0e6' => [
                'zoneName' => 'bar.com',
                'domains' => [
                    [
                        'recordId' => '37cc7f94eebfb4ca4f9002605c145190',
                        'domain' => 'sub-domain1.bar.com',
                        'recordName' => '_acme-challenge.sub-domain1.bar.com.',
                        'recordValue' => 'record_value1',
                    ],
                    [
                        'recordId' => '03d8cb2d898ab5202ce07bc5115d4389',
                        'domain' => '*.sub-domain1.bar.com',
                        'recordName' => '_acme-challenge.sub-domain1.bar.com.',
                        'recordValue' => 'record_value2',
                    ],
                    [
                        'recordId' => '8f8e9dbb183812af0bd45dc895bc4ee8',
                        'domain' => 'sub-domain2.bar.com',
                        'recordName' => '_acme-challenge.sub-domain2.bar.com.',
                        'recordValue' => 'record_value3',
                    ],
                ],
            ],
            /* key - zoneId */
            '167a0418dd8ce3bf0ef00dfb6195f038' => [
                'zoneName' => 'foo.com',
                'domains' => [
                    [
                        'recordId' => '4536b661a67872e2026182eb5d55c6bd',
                        'domain' => 'sub-domain.foo.com',
                        'recordName' => '_acme-challenge.sub-domain.foo.com.',
                        'recordValue' => 'record_value',
                    ],
                ],
            ],
        ];
    }

    protected function createChallengeMocks(array $testData)
    {
        $ret = [];

        foreach ($testData as $zoneData) {
            foreach ($zoneData['domains'] as $domainData) {
                $domain = $domainData['domain'];
                $recordName = $domainData['recordName'];
                $recordValue = $domainData['recordValue'];

                $mockStubChallenge = $this->prophesize(AuthorizationChallenge::class);
                $mockStubChallenge->getDomain()->willReturn($domain);
                $stubChallenge = $mockStubChallenge->reveal();

                $this->mockExtractor->getRecordName($stubChallenge)->willReturn($recordName);
                $this->mockExtractor->getRecordValue($stubChallenge)->willReturn($recordValue);

                $ret[] = $stubChallenge;
            }
        }

        return $ret;
    }

    private function expectZonesQuery(array $testData)
    {
        $zones = [];

        foreach ($testData as $zoneId => $zoneData) {
            $zones[] = ['id' => $zoneId, 'name' => $zoneData['zoneName']];
        }

        $zonesJson = json_encode($zones);
        $zoneCount = count($zones);

        $this->mockClient->request(
            'GET',
            'https://api.cloudflare.com/client/v4/zones',
            [
                'headers' => [
                    'Authorization' => 'Bearer stub_api_key',
                ],
            ]
        )->willReturn($this->getResponseMock(<<<JSON
{
    "errors": [],
    "messages": [],
    "result": {$zonesJson},
    "result_info": {
        "count": {$zoneCount},
        "page": 1,
        "per_page": 20,
        "total_count": {$zoneCount},
        "total_pages": 1
    },
    "success": true
}
JSON
        ))
        ->shouldBeCalled();
    }

    private function expectDnsRecordsQuery($zoneId, $zoneName, array $domains)
    {
        $responseData = [];

        foreach ($domains as $domainData) {
            $responseData[] = $this->buildZoneResponse($zoneName, $domainData);
        }

        $responseDataEncoded = json_encode($responseData);
        $responseDataCount = count($responseData);

        $this->mockClient->request(
            'GET',
            sprintf(
                'https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&comment=%s',
                $zoneId,
                'acmephp-'.$zoneName
            ),
            [
                'headers' => [
                    'Authorization' => 'Bearer stub_api_key',
                ],
            ]
        )->willReturn($this->getResponseMock(<<<JSON
{
    "errors": [],
    "messages": [],
    "result": {$responseDataEncoded},
    "result_info": {
        "count": {$responseDataCount},
        "page": 1,
        "per_page": 100,
        "total_count": {$responseDataCount},
        "total_pages": 1
    },
    "success": true
}
JSON
        ))
            ->shouldBeCalled();
    }

    private function expectDnsRecordsAddition($zoneId, $zoneName, array $domains)
    {
        $postData = $responsePostData = [];

        foreach ($domains as $domainData) {
            $postData[] = [
                'comment' => 'acmephp-'.$zoneName,
                'content' => $domainData['recordValue'],
                'name' => $domainData['recordName'],
                'proxied' => false,
                'ttl' => 60,
                'type' => 'TXT',
            ];

            $responsePostData[] = $this->buildZoneResponse($zoneName, $domainData);
        }

        $responsePostDataEncoded = json_encode($responsePostData);

        $this->mockClient->request(
            'POST',
            'https://api.cloudflare.com/client/v4/zones/'.$zoneId.'/dns_records/batch',
            [
                'headers' => [
                    'Authorization' => 'Bearer stub_api_key',
                ],
                'json' => [
                    'posts' => $postData,
                ],
            ]
        )->willReturn($this->getResponseMock(<<<JSON
{
    "errors": [],
    "messages": [],
    "result": {
        "deletes": null,
        "patches": null,
        "posts": {$responsePostDataEncoded},
        "puts": null
    },
    "success": true
}
JSON
        ))
        ->shouldBeCalled();
    }

    private function expectDnsRecordsDeletion($zoneId, $zoneName, array $domains)
    {
        $postData = $responsePostData = [];

        foreach ($domains as $domainData) {
            $postData[] = [
                'id' => $domainData['recordId'],
            ];

            $responsePostData[] = $this->buildZoneResponse($zoneName, $domainData);
        }

        $responsePostDataEncoded = json_encode($responsePostData);

        $this->mockClient->request(
            'POST',
            'https://api.cloudflare.com/client/v4/zones/'.$zoneId.'/dns_records/batch',
            [
                'headers' => [
                    'Authorization' => 'Bearer stub_api_key',
                ],
                'json' => [
                    'deletes' => $postData,
                ],
            ]
        )->willReturn($this->getResponseMock(<<<JSON
{
    "errors": [],
    "messages": [],
    "result": {
        "deletes": {$responsePostDataEncoded},
        "patches": null,
        "posts": null,
        "puts": null
    },
    "success": true
}
JSON
        ))
        ->shouldBeCalled();
    }

    private function buildZoneResponse($zoneName, array $domainData)
    {
        return [
            'comment' => 'acmephp-'.$zoneName,
            'comment_modified_on' => '2025-09-22T08:16:23.062723Z',
            'content' => $domainData['recordValue'],
            'created_on' => '2025-09-22T08:16:23.062723Z',
            'id' => $domainData['recordId'],
            'meta' => [],
            'modified_on' => '2025-09-22T08:16:23.062723Z',
            'name' => $domainData['recordName'],
            'proxiable' => false,
            'proxied' => false,
            'settings' => [],
            'tags' => [],
            'ttl' => 60,
            'type' => 'TXT',
        ];
    }
}
