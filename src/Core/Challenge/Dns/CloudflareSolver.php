<?php

/*
 * This file is part of the Acme PHP project.
 *
 * (c) Titouan Galopin <galopintitouan@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AcmePhp\Core\Challenge\Dns;

use AcmePhp\Core\Challenge\ConfigurableServiceInterface;
use AcmePhp\Core\Challenge\MultipleChallengesSolverInterface;
use AcmePhp\Core\Exception\Protocol\ChallengeFailedException;
use AcmePhp\Core\Protocol\AuthorizationChallenge;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use Webmozart\Assert\Assert;

/**
 * ACME DNS solver with automate configuration of a Cloudflare.com.
 *
 * @author Alexander Obuhovich <aik.bold@gmail.com>
 */
class CloudflareSolver implements MultipleChallengesSolverInterface, ConfigurableServiceInterface
{
    use LoggerAwareTrait;

    private const COMMENT_PREFIX = 'acmephp';

    /**
     * @var DnsDataExtractor
     */
    private $extractor;

    /**
     * @var ClientInterface
     */
    private $client;

    /**
     * @var array
     */
    private $cacheZones;

    /**
     * @var string
     */
    private $apiKey;

    public function __construct(?DnsDataExtractor $extractor = null, ?ClientInterface $client = null)
    {
        $this->extractor = $extractor ?: new DnsDataExtractor();
        $this->client = $client ?: new Client();
        $this->logger = new NullLogger();
    }

    /**
     * Configure the service with a set of configuration.
     */
    public function configure(array $config)
    {
        $this->apiKey = $config['api_key'];
    }

    public function supports(AuthorizationChallenge $authorizationChallenge): bool
    {
        return 'dns-01' === $authorizationChallenge->getType();
    }

    public function solve(AuthorizationChallenge $authorizationChallenge)
    {
        return $this->solveAll([$authorizationChallenge]);
    }

    public function solveAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        $authorizationChallengesPerZone = $this->groupAuthorizationChallengesPerZone($authorizationChallenges);

        foreach ($authorizationChallengesPerZone as $zoneName => $authorizationChallengesForZone) {
            $batchPostRequests = [];
            $zone = $this->getZone($zoneName);

            foreach ($authorizationChallengesForZone as $authorizationChallenge) {
                $recordName = $this->extractor->getRecordName($authorizationChallenge);
                $recordValue = $this->extractor->getRecordValue($authorizationChallenge);

                $batchPostRequests[] = [
                    'comment' => $this->getDnsRecordComment($zoneName),
                    'content' => $recordValue,
                    'name' => $recordName,
                    'proxied' => false,
                    'ttl' => 60,
                    'type' => 'TXT',
                ];
            }

            $response = $this->client->request(
                'POST',
                'https://api.cloudflare.com/client/v4/zones/'.$zone['id'].'/dns_records/batch',
                [
                    'headers' => [
                        'Authorization' => 'Bearer '.$this->apiKey,
                    ],
                    'json' => [
                        'posts' => $batchPostRequests,
                    ],
                ]
            );
            $responseBodyRaw = $response->getBody()->getContents();
            $responseBodyJson = \json_decode($responseBodyRaw, true);

            if (true === $responseBodyJson['success']) {
                continue;
            }

            throw new ChallengeFailedException(sprintf('Failed to create the DNS records for the "%s" zone.', $zoneName));
        }
    }

    public function cleanup(AuthorizationChallenge $authorizationChallenge)
    {
        return $this->cleanupAll([$authorizationChallenge]);
    }

    public function cleanupAll(array $authorizationChallenges)
    {
        Assert::allIsInstanceOf($authorizationChallenges, AuthorizationChallenge::class);

        $authorizationChallengesPerZone = $this->groupAuthorizationChallengesPerZone($authorizationChallenges);

        foreach (array_keys($authorizationChallengesPerZone) as $zoneName) {
            $zone = $this->getZone($zoneName);
            $this->deleteZoneDnsRecords($zone['id'], $zoneName);
        }
    }

    /**
     * @param AuthorizationChallenge[] $authorizationChallenges
     *
     * @return AuthorizationChallenge[][]
     */
    private function groupAuthorizationChallengesPerZone(array $authorizationChallenges)
    {
        $groups = [];
        foreach ($authorizationChallenges as $authorizationChallenge) {
            $zone = $this->getZone($authorizationChallenge->getDomain());
            $groups[$zone['name']][] = $authorizationChallenge;
        }

        return $groups;
    }

    private function getZone($domain)
    {
        $domainParts = explode('.', $domain);
        $domains = array_reverse(array_map(
            function ($index) use ($domainParts) {
                return implode('.', \array_slice($domainParts, \count($domainParts) - $index));
            },
            range(0, \count($domainParts))
        ));

        $zones = $this->getZones();
        foreach ($domains as $cursorDomain) {
            if (isset($zones[$cursorDomain])) {
                return $zones[$cursorDomain];
            }
        }

        throw new ChallengeFailedException(sprintf('Unable to find a zone for the domain "%s"', $domain));
    }

    private function getZones()
    {
        if (null !== $this->cacheZones) {
            return $this->cacheZones;
        }

        $response = $this->client->request(
            'GET',
            'https://api.cloudflare.com/client/v4/zones',
            [
                'headers' => [
                    'Authorization' => 'Bearer '.$this->apiKey,
                ],
            ]
        );
        $responseBodyRaw = $response->getBody()->getContents();
        $responseBodyJson = \json_decode($responseBodyRaw, true);

        if (true !== $responseBodyJson['success']) {
            throw new ChallengeFailedException('Unable to query zones information');
        }

        $this->cacheZones = [];

        foreach ($responseBodyJson['result'] as $zoneData) {
            $this->cacheZones[$zoneData['name']] = $zoneData;
        }

        return $this->cacheZones;
    }

    private function deleteZoneDnsRecords($zoneId, $domain)
    {
        $zoneDnsRecordIds = $this->getZoneDnsRecordIds($zoneId, $domain);

        if (!$zoneDnsRecordIds) {
            return;
        }

        $batchDeleteRequests = [];

        foreach ($zoneDnsRecordIds as $zoneDnsRecordId) {
            $batchDeleteRequests[] = ['id' => $zoneDnsRecordId];
        }

        $response = $this->client->request(
            'POST',
            sprintf(
                'https://api.cloudflare.com/client/v4/zones/%s/dns_records/batch',
                $zoneId
            ),
            [
                'headers' => [
                    'Authorization' => 'Bearer '.$this->apiKey,
                ],
                'json' => [
                    'deletes' => $batchDeleteRequests,
                ],
            ]
        );
        $responseBodyRaw = $response->getBody()->getContents();
        $responseBodyJson = \json_decode($responseBodyRaw, true);

        if (true === $responseBodyJson['success']) {
            return;
        }

        throw new ChallengeFailedException(sprintf('Failed to delete the DNS records for the "%s" domain.', $domain));
    }

    private function getZoneDnsRecordIds($zoneId, $domain)
    {
        $response = $this->client->request(
            'GET',
            sprintf(
                'https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=TXT&comment=%s',
                $zoneId,
                $this->getDnsRecordComment($domain)
            ),
            [
                'headers' => [
                    'Authorization' => 'Bearer '.$this->apiKey,
                ],
            ]
        );
        $responseBodyRaw = $response->getBody()->getContents();
        $responseBodyJson = \json_decode($responseBodyRaw, true);

        if (true !== $responseBodyJson['success']) {
            throw new ChallengeFailedException(sprintf('Failed to query the DNS records for the "%s" domain.', $domain));
        }

        $ret = [];

        foreach ($responseBodyJson['result'] as $dnsRecord) {
            $ret[] = $dnsRecord['id'];
        }

        return $ret;
    }

    private function getDnsRecordComment($domain)
    {
        return self::COMMENT_PREFIX.'-'.$domain;
    }
}
