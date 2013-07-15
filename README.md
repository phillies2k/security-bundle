P2SecurityBundle
================


### Installation

    "require": {
        "p2/security-bundle": "~1.0"
    }

### Configuration

    p2_security:
        document:   Acme\UserBundle\Document\User   # The user document class
        manager:    @user_manager                   # The service id of your user manager
        encoder:    sha256                          # The encoder algorithm to use

### Usage

Simply extend your user document with the P2 Security user class.

    <?php

    namespace Acme\BlogBundle\Document;

    use P2\Bundle\SecurityBundle\Security\User as SecurityUser;

    class User extends SecurityUser
    {
        // ...
    }

Implement the UserManagerInterface:

    <?php

    namespace Acme\BlogBundle\Repository;

    use P2\Bundle\SecurityBundle\Security\UserManagerInterface;

    class UserRepository extends DocumentRepository implements UserManagerInterface
    {
        // ...
    }
