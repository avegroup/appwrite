<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

// Reference Material
// https://developers.google.com/oauthplayground/
// https://developers.google.com/identity/protocols/OAuth2
// https://developers.google.com/identity/protocols/OAuth2WebServer

class Google extends OAuth2
{
    /**
     * @var string
     */
    protected string $version = 'v4';

    /**
     * @var array
     */
    protected array $scopes = [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'openid'
    ];

    /**
     * @var array
     */
    protected array $user = [];

    /**
     * @var array
     */
    protected array $tokens = [];

    /**
     * @return string
     */
    public function getName(): string
    {
        return 'google';
    }

    /**
     * @return string
     */
    public function getLoginURL(): string
    {
        return 'https://accounts.google.com/o/oauth2/v2/auth?' . \http_build_query([
            'client_id' => $this->appID,
            'redirect_uri' => $this->callback,
            'scope' => \implode(' ', $this->getScopes()),
            'state' => \json_encode($this->state),
            'response_type' => 'code'
        ]);
    }

    /**
     * @param string $code
     *
     * @return array
     */
    protected function getTokens(string $code): array
    {
        if (empty($this->tokens)) {
            $this->tokens = \json_decode($this->request(
                'POST',
                'https://oauth2.googleapis.com/token?' . \http_build_query([
                    'code' => $code,
                    'client_id' => $this->appID,
                    'client_secret' => $this->appSecret,
                    'redirect_uri' => $this->callback,
                    'scope' => null,
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
        $this->tokens = \json_decode($this->request(
            'POST',
            'https://oauth2.googleapis.com/token?' . \http_build_query([
                'refresh_token' => $refreshToken,
                'client_id' => $this->appID,
                'client_secret' => $this->appSecret,
                'grant_type' => 'refresh_token'
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

        return $user['sub'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        return $user['email'] ?? '';
    }

    /**
     * Check if the OAuth email is verified
     *
     * @link https://www.oauth.com/oauth2-servers/signing-in-with-google/verifying-the-user-info/
     *
     * @param string $accessToken
     *
     * @return bool
     */
    public function isEmailVerified(string $accessToken): bool
    {
        $user = $this->getUser($accessToken);

        if ($user['email_verified'] ?? false) {
            return true;
        }

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

        return $user['name'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken): array
    {
        if (empty($this->user)) {
            $user = $this->request('GET', 'https://www.googleapis.com/oauth2/v3/userinfo?access_token=' . \urlencode($accessToken));
            $this->user = \json_decode($user, true);
        }

        return $this->user;
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserPhone(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API может возвращать телефон в поле 'phone_number'
        return $user['phone_number'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserAvatar(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API возвращает аватар в поле 'picture'
        return $user['picture'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserGender(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API возвращает пол в поле 'gender'
        return $user['gender'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserBirthDate(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API возвращает дату рождения в поле 'birthday' (для определенных scopes)
        return $user['birthday'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserCountry(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API возвращает страну в поле 'locale' или 'country' в профиле
        $locale = $user['locale'] ?? '';
        if (!empty($locale) && \strpos($locale, '_') !== false) {
            $parts = \explode('_', $locale);
            return $parts[1] ?? '';
        }

        return $user['country'] ?? '';
    }

    /**
     * @param string $accessToken
     *
     * @return string
     */
    public function getUserCity(string $accessToken): string
    {
        $user = $this->getUser($accessToken);

        // Google API может возвращать город в соответствующих полях профиля
        return $user['city'] ?? '';
    }
}
