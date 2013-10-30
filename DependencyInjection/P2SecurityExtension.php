<?php
/**
 * This file is part of the P2SecurityBundle.
 *
 * (c) 2013 Philipp Boes <mostgreedy@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace P2\Bundle\SecurityBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use Symfony\Component\DependencyInjection\Extension\PrependExtensionInterface;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * Class P2SecurityExtension
 * @package P2\Bundle\SecurityBundle\DependencyInjection
 */
class P2SecurityExtension extends Extension implements PrependExtensionInterface
{
    /**
     * {@inheritDoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        if (! isset($config['manager'])) {
            throw new InvalidArgumentException('manager must be set in p2_security configuration.');
        }

        $container->setAlias('p2_security.security.user_manager', $config['manager']);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');

        $userProviderDefinition = $container->getDefinition('p2_security.security.user_provider');
        $userProviderDefinition->setArguments(array(new Reference('p2_security.security.user_manager')));
    }

    /**
     * {@inheritDoc}
     */
    public function prepend(ContainerBuilder $container)
    {
        $config = $container->getExtensionConfig($this->getAlias());
        $config = $this->processConfiguration(new Configuration(), $config);

        $bundles = $container->getParameter('kernel.bundles');

        if (! isset($bundles['SecurityBundle'])) {
            throw new \RuntimeException('The SecurityBundle is missing from your system.');
        }

        $securityConfig = array(
            'providers' => array(
                'p2_security' => array(
                    'id' => 'p2_security.security.user_provider'
                )
            )
        );

        $securityConfig['encoders'] = array();
        $securityConfig['encoders'][$config['document']] = array(
            'algorithm' => $config['encoder'],
            'encode_as_base64' => false,
            'iterations' => 1
        );

        $container->prependExtensionConfig('security', $securityConfig);
    }
}
