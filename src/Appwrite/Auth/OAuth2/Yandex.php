<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://tech.yandex.com/passport/doc/dg/reference/request-docpage/
// https://tech.yandex.com/oauth/doc/dg/reference/web-client-docpage/


class Yandex extends OAuth2
{
    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @var array
     */
    protected array $scopes = [];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'Yandex';
    }

    /**
     * @param string $state
     *
     * @return array
     */
    public function parseState(string $state)
    {
        return \json_decode(\html_entity_decode($state), true);
    }


    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://oauth.yandex.ru/authorize?' . \http_build_query([
            'response_type' => 'code',
            'client_id' => $this->appID,
            'scope' => \implode(' ', $this->getScopes()),
            'state' => \json_encode($this->state)
        ]);
    }

    /**
     * @param string $code
     *
     * @return string
     */
    protected function getPhone(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Возвращаем номер телефона, если доступен
        // API Яндекса может возвращать телефон в поле 'default_phone' или 'phone'
        $phoneNumber = '';

        if (!empty($user['default_phone']['number'])) {
            $phoneNumber = $user['default_phone']['number']; // Формат вида "+71234567890"
        } elseif (!empty($user['phone']['number'])) {
            $phoneNumber = $user['phone']['number'];
        }

        return $phoneNumber;
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $headers = [
                'Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret),
                'Content-Type: application/x-www-form-urlencoded',
            ];
            $this->tokens = \json_decode($this->request(
                'POST',
                'https://oauth.yandex.ru/token',
                $headers,
                \http_build_query([
                    'code' => $code,
                    'grant_type' => 'authorization_code'
                ])
            ), true);
        }

        return $this->tokens;
    }

    /**
     * @param string $refreshToken
     *
     * @return array
     */
    public function refreshTokens(string $refreshToken): array
    {
        $headers = [
            'Authorization: Basic ' . \base64_encode($this->appID . ':' . $this->appSecret),
            'Content-Type: application/x-www-form-urlencoded',
        ];
        $this->tokens = \json_decode($this->request(
            'POST',
            'https://oauth.yandex.ru/token',
            $headers,
            \http_build_query([
                'refresh_token' => $refreshToken,
                'grant_type' => 'authorization_code'
            ])
        ), true);

        if (empty($this->tokens['refresh_token'])) {
            $this->tokens['refresh_token'] = $refreshToken;
        }

        return $this->tokens;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['id'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['default_email'] ?? '';
    }

    /**
     * Check if the OAuth email is verified
     *
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        return false;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Пробуем разные возможные поля для имени из профиля Яндекса
        $name = '';

        // Приоритет: настоящее имя (если доступно)
        if (!empty($user['real_name'])) {
            $name = $user['real_name'];
        }
        // Затем пробуем составное имя
        elseif (!empty($user['first_name']) && !empty($user['last_name'])) {
            $name = $user['first_name'] . ' ' . $user['last_name'];
        }
        // Только имя
        elseif (!empty($user['first_name'])) {
            $name = $user['first_name'];
        }
        // Только фамилия
        elseif (!empty($user['last_name'])) {
            $name = $user['last_name'];
        }
        // Отображаемое имя (логин)
        elseif (!empty($user['display_name'])) {
            $name = $user['display_name'];
        }

        return $name;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserPhone(string $accessToken): string
    {
        return $this->getPhone($accessToken);
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $user = $this->request('GET', 'https://login.yandex.ru/info?' . \http_build_query([
                'format' => 'json',
                'oauth_token' => $accessToken
            ]));
            $this->user = \json_decode($user, true);
        }
        return $this->user;
    }
}
