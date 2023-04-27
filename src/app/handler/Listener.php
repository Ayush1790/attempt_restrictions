<?php

namespace handler\Listener;

use Phalcon\Di\Injectable;
use Phalcon\Escaper;
use Phalcon\Mvc\Application;
use Phalcon\Events\Event;
use Phalcon\Mvc\Dispatcher;
use Phalcon\Acl\Adapter\Memory;

class Listener extends Injectable
{

    public function dbEvent()
    {
        $escaper = new Escaper();
        $name = $escaper->escapeHtml("$_POST[name]");
        $email = $escaper->escapeHtml("$_POST[email]");
        $pswd = $escaper->escapeHtml("$_POST[pswd]");
        $this->insertLog($_POST['name'], $name);
        $this->insertLog($_POST['email'], $email);
        $this->insertLog($_POST['pswd'], $pswd);
        $_POST['name'] = $name;
        $_POST['email'] = $email;
        $_POST['pswd'] = $pswd;
    }
    public function insertLog($data, $escapedData)
    {
        if ($data != $escapedData) {
            $this->logger->info($data . "<= injected script");
            $this->response->redirect('signup');
        }
    }

    public function storeDataSession()
    {
        $this->session->set("user_email", $this->request->getPost('email'));
        $this->session->set("user_pswd", $this->request->getPost('pswd'));
        $this->cookies->set("isLogin", true, time() + 86400);
    }

    public function setLoginValue()
    {
        if (isset($this->session->user_email)) {
            $_POST['email'] = $this->session->get('user_email');
            $_POST['pswd'] = $this->session->get('user_pswd');
        }
    }

    public function beforeHandleRequest(Event $event, Application $app, Dispatcher $dis)
    {

        $aclFile = APP_PATH . '/security/acl.cache';
        if (true !== is_file($aclFile)) {

            $acl = new Memory();

            /**
             * Add the roles
             */
            $acl->addRole('user');
            $acl->addRole('guest');
            $acl->addRole('manager');
            $acl->addRole('admin');

            /**
             * Add the Components
             */

            $acl->addComponent(
                'dashbord',
                [
                    'index',
                ]
            );

            $acl->addComponent(
                'index',
                [
                    'index'
                ]
            );

            $acl->addComponent(
                'login',
                [
                    'index',
                    'login'
                ]
            );
            $acl->addComponent(
                'signup',
                [
                    'index',
                    'register'
                ]
            );
            $acl->addComponent(
                'logout',
                [
                    'index'
                ]
            );

            $acl->addComponent(
                'admin',
                [
                    'index'
                ]
            );
            $acl->addComponent(
                'finance',
                [
                    'index'
                ]
            );
            $acl->addComponent(
                'manager',
                [
                    'index'
                ]
            );

            $acl->allow('admin', '*', '*');
            $acl->allow('user', 'logout', 'index');
            $acl->allow('*', 'login', '*');
            $acl->allow('user', 'dashbord', '*');
            $acl->allow('manager', 'finance', '*');
            $acl->allow('manager', 'manager', '*');
            $acl->allow('*', 'index', '*');

            file_put_contents(
                $aclFile,
                serialize($acl)
            );
        } else {
            // Restore ACL object from serialized file
            $acl = unserialize(
                file_get_contents($aclFile)
            );
        }
        $role = "guest";
        $controller = "index";
        $action = "index";
        if (!empty($dis->getControllerName())) {
            $controller = $dis->getControllerName();
        }
        if (!empty($dis->getActionName())) {
            $action = $dis->getActionName();
        }
        if (!empty($app->request->get('role'))) {
            $role = $app->request->get('role');
        } else {
            if ($this->cookies->has('loginId')) {
                $role = 'user';
            }
        }
        $id = (string)$this->cookies->get('loginId');
        if ($this->session->get('userDetail')[$id] == 3) {
            echo "blocked ! you exceeds your limit....";
            die;
        } elseif (true === $acl->isAllowed($role, $controller, $action)) {
            //redirect to view
        } else {
            if ($role == 'user') {
                $c = (int)($this->session->get('userDetail')[$id]);
                $c++;
                foreach ($this->session->get('userDetail') as $key => $value) {
                    if ($value == $this->session->get('userDetail')[(string)$this->cookies->get('loginId')]) {
                        $this->session->set('userDetail'[$id], $c);
                        $_SESSION['userDetail'][$id] = $c;
                    }
                }
            }
            echo 'Access denied :(';
            die;
        }
    }
}
