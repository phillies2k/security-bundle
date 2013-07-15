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

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface as SecurityUserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface
{
    /**
     * @var UserManagerInterface $userManager
     */
    protected $userManager;

    /**
     * @param UserManagerInterface $userManager
     */
    public function __construct(UserManagerInterface $userManager)
    {
        $this->userManager = $userManager;
    }

    /**
     * {@inheritDoc}
     */
    public function loadUserByUsername($username)
    {
        if (null === $user = $this->userManager->findByEmailOrUsername($username)) {
            throw new UsernameNotFoundException(sprintf('Could not find user: %s', $username));
        }

        return $user;
    }

    /**
     * {@inheritDoc}
     */
    public function refreshUser(SecurityUserInterface $user)
    {
        $class = get_class($user);

        if (! $this->supportsClass($class)) {
            throw new UnsupportedUserException(sprintf('Unsupported user class: %s', $class));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritDoc}
     */
    public function supportsClass($class)
    {
        return $class === $this->userManager->getClassname();
    }
}