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
     * {@inheritDoc}
     */
    public function getRoles()
    {
        return $this->roles;
    }

    /**
     * @param string $username
     * @return $this
     */
    public function setUsername($username)
    {
        $this->username = $username;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * @param string $email
     * @return $this
     */
    public function setEmail($email)
    {
        $this->email = $email;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @param string $password
     * @return $this
     */
    public function setPassword($password)
    {
        $this->password = $password;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * @param string $salt
     * @return $this
     */
    public function setSalt($salt)
    {
        $this->salt = $salt;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getSalt()
    {
        return $this->salt;
    }

    /**
     * Set enabled
     *
     * @param boolean $enabled
     * @return $this
     */
    public function setEnabled($enabled)
    {
        $this->enabled = $enabled;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function isEnabled()
    {
        return $this->enabled;
    }

    /**
     * {@inheritDoc}
     */
    public function isAccountNonExpired()
    {
        return $this->isEnabled();
    }

    /**
     * {@inheritDoc}
     */
    public function isAccountNonLocked()
    {
        return $this->isEnabled();
    }

    /**
     * {@inheritDoc}
     */
    public function isCredentialsNonExpired()
    {
        return $this->isEnabled();
    }

    /**
     * {@inheritDoc}
     */
    public function eraseCredentials()
    {
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
}
