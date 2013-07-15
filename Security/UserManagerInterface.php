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

interface UserManagerInterface
{
    /**
     * Returns a UserInterface instance found by the email or username.
     *
     * @param string $emailOrUsername
     *
     * @return \P2\Bundle\SecurityBundle\Security\UserInterface
     */
    public function findByEmailOrUsername($emailOrUsername);

    /**
     * Returns the class name of the object managed by this user manager.
     *
     * @return string The class name.
     */
    public function getClassname();
}
