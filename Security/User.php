<?php
/**
 * This file is part of the P2SecurityBundle.
 *
 * (c) 2013 Philipp Boes <mostgreedy@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace P2\Bundle\SecurityBundle\Security;

use Symfony\Component\Security\Core\Role\Role;
use Symfony\Component\Security\Core\User\UserInterface as SecurityUserInterface;

/**
 * Class User
 * @package P2\Bundle\SecurityBundle\Security
 */
abstract class User implements UserInterface
{
    /**
     * @var string
     */
    const ROLE_USER = 'ROLE_USER';

    /**
     * @var string
     */
    const ROLE_ADMIN = 'ROLE_ADMIN';

    /**
     * @var array
     */
    protected static $userRoles = array(
        self::ROLE_USER,
        self::ROLE_ADMIN
    );

    /**
     * @return array
     */
    public static function getUserRoles()
    {
        return static::$userRoles;
    }

    /**
     * @var Role[]
     */
    protected $roles = array();

    /**
     * @var string $email
     */
    protected $email;

    /**
     * @var string $username
     */
    protected $username;

    /**
     * @var string $password
     */
    protected $password;

    /**
     * @var string $salt
     */
    protected $salt;

    /**
     * @var boolean $enabled
     */
    protected $enabled = false;

    /**
     * @param string $role
     */
    public function __construct($role = self::ROLE_USER)
    {
        $this->setRole($role);
        $this->salt = hash('sha256', uniqid(microtime(true)));
    }

    /**
     * Sets a role to this user.
     *
     * @param $role
     *
     * @return UserInterface
     * @throws \InvalidArgumentException
     */
    public function setRole($role)
    {
        if (! in_array($role, static::getUserRoles())) {
            throw new \InvalidArgumentException(sprintf('Invalid user role: %s.', $role));
        }

        if (! in_array($role, $this->roles)) {
            $this->roles[] = (string) $role;
        }

        return $this;
    }

    /**
     * Removes a role from this user.
     *
     * @param $role
     *
     * @return bool True on success, false otherwise.
     */
    public function removeRole($role)
    {
        if (false !== $pos = array_search((string) $role, $this->roles)) {
            unset($this->roles[$pos]);

            return true;
        }

        return false;
    }

    /**
     * Returns the roles granted to the user.
     *
     * <code>
     * public function getRoles()
     * {
     *     return array('ROLE_USER');
     * }
     * </code>
     *
     * Alternatively, the roles might be stored on a ``roles`` property,
     * and populated in any number of different ways when the user object
     * is created.
     *
     * @return Role[] The user roles
     */
    public function getRoles()
    {
        return $this->roles;
    }


    /**
     * @param string $password
     * @return self
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * Checks whether the user's account has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw an AccountExpiredException and prevent login.
     *
     * @return Boolean true if the user's account is non expired, false otherwise
     *
     * @see AccountExpiredException
     */
    public function isAccountNonExpired()
    {
        return $this->isEnabled();
    }

    /**
     * Checks whether the user is locked.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a LockedException and prevent login.
     *
     * @return Boolean true if the user is not locked, false otherwise
     *
     * @see LockedException
     */
    public function isAccountNonLocked()
    {
        return $this->isEnabled();
    }

    /**
     * Checks whether the user's credentials (password) has expired.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a CredentialsExpiredException and prevent login.
     *
     * @return Boolean true if the user's credentials are non expired, false otherwise
     *
     * @see CredentialsExpiredException
     */
    public function isCredentialsNonExpired()
    {
        return $this->isEnabled();
    }

    /**
     * Removes sensitive data from the user.
     *
     * This is important if, at any given point, sensitive information like
     * the plain-text password is stored on this object.
     *
     * @return void
     */
    public function eraseCredentials()
    {
    }

    /**
     * Checks whether the user is enabled.
     *
     * Internally, if this method returns false, the authentication system
     * will throw a DisabledException and prevent login.
     *
     * @return Boolean true if the user is enabled, false otherwise
     *
     * @see DisabledException
     */
    public function isEnabled()
    {
        return $this->enabled;
    }

    /**
     * {@inheritDoc}
     */
    public function isEqualTo(SecurityUserInterface $user)
    {
        if ($this->getUsername() !== $user->getUsername()) {

            return false;
        }

        if ($this->getPassword() !== $user->getPassword()) {

            return false;
        }

        if ($this->getSalt() !== $user->getSalt()) {

            return false;
        }

        return true;
    }

    /**
     * Returns the password used to authenticate the user.
     *
     * This should be the encoded password. On authentication, a plain-text
     * password will be salted, encoded, and then compared to this value.
     *
     * @return string The password
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Returns the salt that was originally used to encode the password.
     *
     * This can return null if the password was not encoded using a salt.
     *
     * @return string The salt
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * Returns the username used to authenticate the user.
     *
     * @return string The username
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Returns the email address used to authenticate this user.
     *
     * @return string The email address.
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param string $email
     * @return self
     */
    public function setEmail($email)
    {
        $this->email = $email;

        return $this;
    }

    /**
     * @param string $username
     * @return self
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * Set enabled
     *
     * @param boolean $enabled
     * @return self
     */
    public function setEnabled($enabled)
    {
        $this->enabled = $enabled;

        return $this;
    }
}
