package org.apache.syncope.core.spring.policy;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DefaultPasswordRuleRegression1 {

    public static boolean debug = false;

    public void assertBooleanArrayEquals(boolean[] expectedArray, boolean[] actualArray) {
        if (expectedArray.length != actualArray.length) {
            throw new AssertionError("Array lengths differ: " + expectedArray.length + " != " + actualArray.length);
        }
        for (int i = 0; i < expectedArray.length; i++) {
            if (expectedArray[i] != actualArray[i]) {
                throw new AssertionError("Arrays differ at index " + i + ": " + expectedArray[i] + " != " + actualArray[i]);
            }
        }
    }

    @Test
    public void test501() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test501");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Class<?> wildcardClass14 = encryptorManager13.getClass();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test502() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test502");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test503() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test503");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test504() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test504");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.User user10 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user10, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager9);
    }

    @Test
    public void test505() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test505");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
    }

    @Test
    public void test506() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test506");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        java.lang.Class<?> wildcardClass11 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNotNull(wildcardClass11);
    }

    @Test
    public void test507() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test507");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user6 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user6, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test508() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test508");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.entity.user.User user9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user9, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test509() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test509");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test510() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test510");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test511() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test511");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test512() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test512");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.entity.user.User user8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user8, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
    }

    @Test
    public void test513() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test513");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(passwordRuleConf15);
    }

    @Test
    public void test514() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test514");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
    }

    @Test
    public void test515() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test515");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test516() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test516");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.junit.Assert.assertNull(passwordRuleConf3);
    }

    @Test
    public void test517() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test517");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test518() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test518");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test519() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test519");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf17 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf17;
        java.lang.Class<?> wildcardClass19 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager15);
        org.junit.Assert.assertNull(passwordRuleConf16);
        org.junit.Assert.assertNotNull(wildcardClass19);
    }

    @Test
    public void test520() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test520");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test521() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test521");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.junit.Assert.assertNull(encryptorManager3);
    }

    @Test
    public void test522() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test522");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Class<?> wildcardClass12 = passwordValidator11.getClass();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test523() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test523");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
    }

    @Test
    public void test524() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test524");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        java.lang.String[] strArray11 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet12 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean13 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet12, strArray11);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNotNull(strArray11);
        org.junit.Assert.assertArrayEquals(strArray11, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean13 + "' != '" + true + "'", boolean13 == true);
    }

    @Test
    public void test525() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test525");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test526() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test526");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test527() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test527");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test528() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test528");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf16;
        java.lang.String[] strArray21 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet22 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean23 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet22, strArray21);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet22);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNotNull(strArray21);
        org.junit.Assert.assertArrayEquals(strArray21, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean23 + "' != '" + true + "'", boolean23 == true);
    }

    @Test
    public void test529() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test529");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordValidator11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test530() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test530");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test531() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test531");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test532() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test532");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount1 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount1);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test533() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test533");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test534() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test534");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf5);
    }

    @Test
    public void test535() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test535");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user14, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test536() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test536");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test537() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test537");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test538() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test538");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Class<?> wildcardClass11 = passwordRuleConf10.getClass();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test539() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test539");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        java.lang.String[] strArray11 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet12 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean13 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet12, strArray11);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNotNull(strArray11);
        org.junit.Assert.assertArrayEquals(strArray11, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean13 + "' != '" + true + "'", boolean13 == true);
    }

    @Test
    public void test540() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test540");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        java.lang.String[] strArray14 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet15 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean16 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet15, strArray14);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet15);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNotNull(strArray14);
        org.junit.Assert.assertArrayEquals(strArray14, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean16 + "' != '" + true + "'", boolean16 == true);
    }

    @Test
    public void test541() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test541");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager17 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager18 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager17);
        org.junit.Assert.assertNull(encryptorManager18);
    }

    @Test
    public void test542() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test542");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test543() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test543");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Class<?> wildcardClass12 = encryptorManager11.getClass();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test544() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test544");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager4);
    }

    @Test
    public void test545() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test545");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf5);
    }

    @Test
    public void test546() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test546");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
    }

    @Test
    public void test547() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test547");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf15 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator16 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator16;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(defaultPasswordRuleConf15);
    }

    @Test
    public void test548() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test548");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test549() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test549");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        java.lang.String[] strArray15 = new java.lang.String[] { "hi!", "" };
        java.util.LinkedHashSet<java.lang.String> strSet16 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean17 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet16, strArray15);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet16);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNotNull(strArray15);
        org.junit.Assert.assertArrayEquals(strArray15, new java.lang.String[] { "hi!", "" });
        org.junit.Assert.assertTrue("'" + boolean17 + "' != '" + true + "'", boolean17 == true);
    }

    @Test
    public void test550() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test550");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test551() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test551");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
    }

    @Test
    public void test552() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test552");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.junit.Assert.assertNull(passwordRuleConf3);
    }

    @Test
    public void test553() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test553");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.User user9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user9, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test554() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test554");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test555() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test555");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test556() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test556");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test557() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test557");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
    }

    @Test
    public void test558() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test558");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test559() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test559");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.passay.PasswordValidator passwordValidator15 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator15;
        org.passay.PasswordValidator passwordValidator17 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator17;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test560() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test560");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(encryptorManager12);
    }

    @Test
    public void test561() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test561");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test562() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test562");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager12);
    }

    @Test
    public void test563() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test563");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager10);
    }

    @Test
    public void test564() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test564");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        java.lang.String[] strArray9 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet10 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean11 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet10, strArray9);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNotNull(strArray9);
        org.junit.Assert.assertArrayEquals(strArray9, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean11 + "' != '" + true + "'", boolean11 == true);
    }

    @Test
    public void test565() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test565");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test566() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test566");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount5 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount5);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test567() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test567");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test568() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test568");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test569() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test569");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test570() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test570");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        java.lang.String[] strArray13 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet14 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean15 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet14, strArray13);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNotNull(strArray13);
        org.junit.Assert.assertArrayEquals(strArray13, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean15 + "' != '" + true + "'", boolean15 == true);
    }

    @Test
    public void test571() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test571");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf12);
    }

    @Test
    public void test572() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test572");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test573() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test573");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator5);
    }

    @Test
    public void test574() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test574");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager14);
    }

    @Test
    public void test575() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test575");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test576() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test576");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test577() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test577");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user10 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user10, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test578() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test578");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        java.lang.String[] strArray18 = new java.lang.String[] { "hi!", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet19 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean20 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet19, strArray18);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet19);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
        org.junit.Assert.assertNotNull(strArray18);
        org.junit.Assert.assertArrayEquals(strArray18, new java.lang.String[] { "hi!", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean20 + "' != '" + true + "'", boolean20 == true);
    }

    @Test
    public void test579() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test579");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test580() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test580");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test581() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test581");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf12);
    }

    @Test
    public void test582() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test582");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        java.lang.Class<?> wildcardClass12 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
        org.junit.Assert.assertNotNull(wildcardClass12);
    }

    @Test
    public void test583() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test583");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        java.lang.Class<?> wildcardClass9 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNotNull(wildcardClass9);
    }

    @Test
    public void test584() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test584");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator14 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(passwordValidator13);
        org.junit.Assert.assertNull(passwordValidator14);
    }

    @Test
    public void test585() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test585");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        java.lang.Class<?> wildcardClass15 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNotNull(wildcardClass15);
    }

    @Test
    public void test586() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test586");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test587() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test587");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        java.lang.Class<?> wildcardClass12 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNotNull(wildcardClass12);
    }

    @Test
    public void test588() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test588");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test589() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test589");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
    }

    @Test
    public void test590() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test590");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
    }

    @Test
    public void test591() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test591");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test592() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test592");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test593() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test593");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user17, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager15);
        org.junit.Assert.assertNull(passwordRuleConf16);
    }

    @Test
    public void test594() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test594");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        java.lang.Class<?> wildcardClass6 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNotNull(wildcardClass6);
    }

    @Test
    public void test595() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test595");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
    }

    @Test
    public void test596() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test596");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager10);
    }

    @Test
    public void test597() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test597");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        java.lang.String[] strArray14 = new java.lang.String[] { "", "" };
        java.util.LinkedHashSet<java.lang.String> strSet15 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean16 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet15, strArray14);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet15);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNotNull(strArray14);
        org.junit.Assert.assertArrayEquals(strArray14, new java.lang.String[] { "", "" });
        org.junit.Assert.assertTrue("'" + boolean16 + "' != '" + true + "'", boolean16 == true);
    }

    @Test
    public void test598() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test598");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.User user9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user9, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test599() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test599");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test600() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test600");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test601() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test601");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf15 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf15);
    }

    @Test
    public void test602() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test602");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.passay.PasswordValidator passwordValidator16 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordValidator16);
    }

    @Test
    public void test603() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test603");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
    }

    @Test
    public void test604() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test604");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        java.lang.String[] strArray14 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet15 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean16 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet15, strArray14);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet15);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNotNull(strArray14);
        org.junit.Assert.assertArrayEquals(strArray14, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean16 + "' != '" + true + "'", boolean16 == true);
    }

    @Test
    public void test605() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test605");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test606() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test606");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test607() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test607");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordValidator6);
    }

    @Test
    public void test608() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test608");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test609() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test609");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
    }

    @Test
    public void test610() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test610");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test611() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test611");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test612() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test612");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test613() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test613");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
    }

    @Test
    public void test614() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test614");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test615() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test615");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        java.lang.String[] strArray10 = new java.lang.String[] { "hi!", "" };
        java.util.LinkedHashSet<java.lang.String> strSet11 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean12 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet11, strArray10);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNotNull(strArray10);
        org.junit.Assert.assertArrayEquals(strArray10, new java.lang.String[] { "hi!", "" });
        org.junit.Assert.assertTrue("'" + boolean12 + "' != '" + true + "'", boolean12 == true);
    }

    @Test
    public void test616() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test616");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test617() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test617");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        java.lang.Class<?> wildcardClass6 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNotNull(wildcardClass6);
    }

    @Test
    public void test618() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test618");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test619() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test619");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test620() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test620");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf16);
    }

    @Test
    public void test621() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test621");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        java.lang.Class<?> wildcardClass11 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNotNull(wildcardClass11);
    }

    @Test
    public void test622() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test622");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf6 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf6);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test623() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test623");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test624() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test624");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.core.persistence.api.entity.user.User user14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user14, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
    }

    @Test
    public void test625() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test625");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        java.lang.String[] strArray14 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet15 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean16 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet15, strArray14);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!", (java.util.Set<java.lang.String>) strSet15);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNotNull(strArray14);
        org.junit.Assert.assertArrayEquals(strArray14, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean16 + "' != '" + true + "'", boolean16 == true);
    }

    @Test
    public void test626() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test626");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.entity.user.User user9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user9, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
    }

    @Test
    public void test627() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test627");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.passay.PasswordValidator passwordValidator16 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator16);
    }

    @Test
    public void test628() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test628");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test629() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test629");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
        org.junit.Assert.assertNull(passwordRuleConf15);
    }

    @Test
    public void test630() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test630");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        java.lang.String[] strArray16 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet17 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean18 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet17, strArray16);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
        org.junit.Assert.assertNotNull(strArray16);
        org.junit.Assert.assertArrayEquals(strArray16, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean18 + "' != '" + true + "'", boolean18 == true);
    }

    @Test
    public void test631() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test631");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager17 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager17;
        org.apache.syncope.core.persistence.api.entity.user.User user19 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user19, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
    }

    @Test
    public void test632() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test632");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
    }

    @Test
    public void test633() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test633");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        java.lang.Class<?> wildcardClass11 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNotNull(wildcardClass11);
    }

    @Test
    public void test634() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test634");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager16 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(passwordRuleConf15);
        org.junit.Assert.assertNull(encryptorManager16);
    }

    @Test
    public void test635() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test635");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test636() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test636");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test637() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test637");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test638() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test638");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test639() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test639");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordValidator4);
    }

    @Test
    public void test640() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test640");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test641() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test641");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.passay.PasswordValidator passwordValidator17 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator17);
    }

    @Test
    public void test642() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test642");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test643() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test643");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        java.lang.String[] strArray12 = new java.lang.String[] { "hi!", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet13 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean14 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet13, strArray12);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNotNull(strArray12);
        org.junit.Assert.assertArrayEquals(strArray12, new java.lang.String[] { "hi!", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean14 + "' != '" + true + "'", boolean14 == true);
    }

    @Test
    public void test644() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test644");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test645() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test645");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test646() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test646");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test647() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test647");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
        org.junit.Assert.assertNull(encryptorManager15);
        org.junit.Assert.assertNull(passwordRuleConf16);
    }

    @Test
    public void test648() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test648");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
    }

    @Test
    public void test649() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test649");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        java.lang.Class<?> wildcardClass7 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNotNull(wildcardClass7);
    }

    @Test
    public void test650() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test650");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf12);
    }

    @Test
    public void test651() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test651");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test652() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test652");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test653() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test653");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        java.lang.Class<?> wildcardClass13 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNotNull(wildcardClass13);
    }

    @Test
    public void test654() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test654");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
    }

    @Test
    public void test655() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test655");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test656() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test656");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test657() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test657");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test658() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test658");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test659() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test659");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
    }

    @Test
    public void test660() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test660");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test661() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test661");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test662() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test662");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        java.lang.Class<?> wildcardClass15 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNotNull(wildcardClass15);
    }

    @Test
    public void test663() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test663");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test664() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test664");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test665() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test665");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test666() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test666");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test667() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test667");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager15);
        org.junit.Assert.assertNull(defaultPasswordRuleConf16);
    }

    @Test
    public void test668() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test668");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        java.lang.Class<?> wildcardClass9 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNotNull(wildcardClass9);
    }

    @Test
    public void test669() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test669");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        java.lang.Class<?> wildcardClass9 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNotNull(wildcardClass9);
    }

    @Test
    public void test670() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test670");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test671() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test671");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test672() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test672");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        java.lang.String[] strArray9 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet10 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean11 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet10, strArray9);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNotNull(strArray9);
        org.junit.Assert.assertArrayEquals(strArray9, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean11 + "' != '" + true + "'", boolean11 == true);
    }

    @Test
    public void test673() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test673");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        java.util.Set<java.lang.String> strSet13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", strSet13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test674() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test674");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user7 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user7, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordValidator6);
    }

    @Test
    public void test675() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test675");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test676() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test676");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        java.lang.Class<?> wildcardClass10 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNotNull(wildcardClass10);
    }

    @Test
    public void test677() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test677");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.junit.Assert.assertNull(passwordValidator5);
    }

    @Test
    public void test678() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test678");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user8, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test679() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test679");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test680() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test680");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test681() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test681");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.passay.PasswordValidator passwordValidator15 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator15;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager17 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager17;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test682() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test682");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test683() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test683");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordValidator5);
    }

    @Test
    public void test684() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test684");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = defaultPasswordRule0.getConf();
        java.lang.String[] strArray19 = new java.lang.String[] { "", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet20 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean21 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet20, strArray19);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet20);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf14);
        org.junit.Assert.assertNotNull(strArray19);
        org.junit.Assert.assertArrayEquals(strArray19, new java.lang.String[] { "", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean21 + "' != '" + true + "'", boolean21 == true);
    }

    @Test
    public void test685() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test685");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test686() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test686");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        java.lang.Class<?> wildcardClass6 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNotNull(wildcardClass6);
    }

    @Test
    public void test687() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test687");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test688() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test688");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test689() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test689");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test690() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test690");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test691() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test691");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf17 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf17;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf19 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf19;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf16);
    }

    @Test
    public void test692() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test692");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
    }

    @Test
    public void test693() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test693");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test694() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test694");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator16 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator16;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
        org.junit.Assert.assertNull(encryptorManager15);
    }

    @Test
    public void test695() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test695");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test696() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test696");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
    }

    @Test
    public void test697() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test697");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf3);
    }

    @Test
    public void test698() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test698");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.User user6 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user6, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test699() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test699");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test700() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test700");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test701() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test701");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.passay.PasswordValidator passwordValidator15 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator15;
        org.passay.PasswordValidator passwordValidator17 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator17;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test702() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test702");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test703() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test703");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test704() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test704");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        java.lang.Class<?> wildcardClass11 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNotNull(wildcardClass11);
    }

    @Test
    public void test705() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test705");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordValidator12);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test706() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test706");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test707() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test707");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test708() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test708");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test709() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test709");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.passay.PasswordValidator passwordValidator16 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(passwordValidator16);
    }

    @Test
    public void test710() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test710");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager3);
    }

    @Test
    public void test711() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test711");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test712() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test712");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test713() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test713");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager16 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager16;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf18 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(passwordRuleConf15);
        org.junit.Assert.assertNull(passwordRuleConf18);
    }

    @Test
    public void test714() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test714");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf15 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(passwordRuleConf14);
        org.junit.Assert.assertNull(defaultPasswordRuleConf15);
    }

    @Test
    public void test715() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test715");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        java.lang.String[] strArray17 = new java.lang.String[] { "", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet18 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean19 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet18, strArray17);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet18);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNotNull(strArray17);
        org.junit.Assert.assertArrayEquals(strArray17, new java.lang.String[] { "", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean19 + "' != '" + true + "'", boolean19 == true);
    }

    @Test
    public void test716() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test716");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test717() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test717");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
        org.junit.Assert.assertNull(passwordRuleConf14);
    }

    @Test
    public void test718() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test718");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf14;
        org.passay.PasswordValidator passwordValidator16 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator16;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test719() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test719");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        java.lang.String[] strArray19 = new java.lang.String[] { "hi!", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet20 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean21 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet20, strArray19);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet20);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNotNull(strArray19);
        org.junit.Assert.assertArrayEquals(strArray19, new java.lang.String[] { "hi!", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean21 + "' != '" + true + "'", boolean21 == true);
    }

    @Test
    public void test720() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test720");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test721() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test721");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordValidator5);
    }

    @Test
    public void test722() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test722");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        java.lang.Class<?> wildcardClass12 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNotNull(wildcardClass12);
    }

    @Test
    public void test723() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test723");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test724() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test724");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test725() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test725");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf10);
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test726() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test726");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.junit.Assert.assertNull(passwordRuleConf3);
    }

    @Test
    public void test727() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test727");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf2 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator3 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator3);
        org.junit.Assert.assertNull(passwordRuleConf4);
    }

    @Test
    public void test728() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test728");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test729() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test729");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator12);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test730() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test730");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
    }

    @Test
    public void test731() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test731");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test732() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test732");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test733() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test733");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(encryptorManager12);
        org.junit.Assert.assertNull(passwordRuleConf15);
    }

    @Test
    public void test734() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test734");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test735() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test735");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        java.lang.String[] strArray17 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet18 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean19 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet18, strArray17);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet18);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager12);
        org.junit.Assert.assertNull(encryptorManager13);
        org.junit.Assert.assertNotNull(strArray17);
        org.junit.Assert.assertArrayEquals(strArray17, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean19 + "' != '" + true + "'", boolean19 == true);
    }

    @Test
    public void test736() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test736");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.passay.PasswordValidator passwordValidator12 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator12);
    }

    @Test
    public void test737() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test737");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        java.lang.String[] strArray17 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet18 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean19 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet18, strArray17);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet18);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNotNull(strArray17);
        org.junit.Assert.assertArrayEquals(strArray17, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean19 + "' != '" + true + "'", boolean19 == true);
    }

    @Test
    public void test738() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test738");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
        org.junit.Assert.assertNull(encryptorManager14);
    }

    @Test
    public void test739() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test739");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test740() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test740");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.User user15 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user15, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
    }

    @Test
    public void test741() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test741");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.entity.user.User user14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user14, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test742() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test742");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test743() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test743");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test744() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test744");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test745() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test745");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
    }

    @Test
    public void test746() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test746");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf12);
    }

    @Test
    public void test747() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test747");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test748() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test748");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        java.lang.Class<?> wildcardClass7 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNotNull(wildcardClass7);
    }

    @Test
    public void test749() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test749");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager10);
    }

    @Test
    public void test750() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test750");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test751() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test751");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test752() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test752");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test753() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test753");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf15 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
        org.junit.Assert.assertNull(defaultPasswordRuleConf15);
        org.junit.Assert.assertNull(passwordRuleConf16);
    }

    @Test
    public void test754() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test754");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test755() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test755");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
    }

    @Test
    public void test756() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test756");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test757() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test757");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test758() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test758");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
    }

    @Test
    public void test759() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test759");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test760() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test760");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
    }

    @Test
    public void test761() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test761");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf10);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test762() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test762");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        java.lang.String[] strArray13 = new java.lang.String[] { "" };
        java.util.LinkedHashSet<java.lang.String> strSet14 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean15 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet14, strArray13);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNotNull(strArray13);
        org.junit.Assert.assertArrayEquals(strArray13, new java.lang.String[] { "" });
        org.junit.Assert.assertTrue("'" + boolean15 + "' != '" + true + "'", boolean15 == true);
    }

    @Test
    public void test763() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test763");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test764() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test764");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test765() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test765");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test766() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test766");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
    }

    @Test
    public void test767() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test767");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf14);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test768() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test768");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user12, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test769() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test769");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf13);
    }

    @Test
    public void test770() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test770");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test771() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test771");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test772() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test772");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordValidator6);
    }

    @Test
    public void test773() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test773");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.passay.PasswordValidator passwordValidator15 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator15;
        org.passay.PasswordValidator passwordValidator17 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator18 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator18;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator17);
    }

    @Test
    public void test774() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test774");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
    }

    @Test
    public void test775() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test775");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test776() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test776");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        java.lang.Class<?> wildcardClass10 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNotNull(wildcardClass10);
    }

    @Test
    public void test777() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test777");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        java.lang.Class<?> wildcardClass9 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNotNull(wildcardClass9);
    }

    @Test
    public void test778() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test778");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.entity.user.User user9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user9, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test779() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test779");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test780() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test780");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test781() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test781");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordRuleConf11);
    }

    @Test
    public void test782() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test782");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test783() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test783");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount9 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount9);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test784() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test784");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(defaultPasswordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
    }

    @Test
    public void test785() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test785");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            java.lang.Class<?> wildcardClass14 = passwordValidator13.getClass();
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test786() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test786");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
    }

    @Test
    public void test787() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test787");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager12);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test788() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test788");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount7 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
    }

    @Test
    public void test789() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test789");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
    }

    @Test
    public void test790() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test790");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test791() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test791");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = defaultPasswordRule0.conf;
        java.lang.String[] strArray10 = new java.lang.String[] { "hi!", "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet11 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean12 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet11, strArray10);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!", (java.util.Set<java.lang.String>) strSet11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf5);
        org.junit.Assert.assertNotNull(strArray10);
        org.junit.Assert.assertArrayEquals(strArray10, new java.lang.String[] { "hi!", "hi!" });
        org.junit.Assert.assertTrue("'" + boolean12 + "' != '" + true + "'", boolean12 == true);
    }

    @Test
    public void test792() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test792");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test793() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test793");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test794() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test794");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test795() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test795");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf15 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(defaultPasswordRuleConf15);
        org.junit.Assert.assertNull(defaultPasswordRuleConf16);
    }

    @Test
    public void test796() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test796");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.passay.PasswordValidator passwordValidator15 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf16 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf17 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator15);
        org.junit.Assert.assertNull(passwordRuleConf16);
        org.junit.Assert.assertNull(passwordRuleConf17);
    }

    @Test
    public void test797() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test797");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.entity.user.User user13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user13, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
    }

    @Test
    public void test798() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test798");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test799() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test799");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf16;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager18 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager18;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager12);
        org.junit.Assert.assertNull(passwordRuleConf15);
    }

    @Test
    public void test800() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test800");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test801() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test801");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test802() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test802");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        java.lang.Class<?> wildcardClass10 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNotNull(wildcardClass10);
    }

    @Test
    public void test803() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test803");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test804() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test804");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        java.lang.String[] strArray12 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet13 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean14 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet13, strArray12);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNotNull(strArray12);
        org.junit.Assert.assertArrayEquals(strArray12, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean14 + "' != '" + true + "'", boolean14 == true);
    }

    @Test
    public void test805() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test805");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordValidator11);
        org.junit.Assert.assertNull(passwordRuleConf14);
    }

    @Test
    public void test806() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test806");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test807() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test807");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
    }

    @Test
    public void test808() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test808");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf6 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordRuleConf6);
    }

    @Test
    public void test809() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test809");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.passay.PasswordValidator passwordValidator12 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator12;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf14 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf14);
    }

    @Test
    public void test810() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test810");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.User user11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user11, "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test811() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test811");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
    }

    @Test
    public void test812() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test812");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf16;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf18 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(encryptorManager12);
        org.junit.Assert.assertNull(passwordRuleConf15);
        org.junit.Assert.assertNull(passwordRuleConf18);
    }

    @Test
    public void test813() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test813");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator5);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test814() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test814");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
    }

    @Test
    public void test815() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test815");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        java.lang.String[] strArray11 = new java.lang.String[] { "hi!" };
        java.util.LinkedHashSet<java.lang.String> strSet12 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean13 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet12, strArray11);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet12);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNotNull(strArray11);
        org.junit.Assert.assertArrayEquals(strArray11, new java.lang.String[] { "hi!" });
        org.junit.Assert.assertTrue("'" + boolean13 + "' != '" + true + "'", boolean13 == true);
    }

    @Test
    public void test816() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test816");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.passay.PasswordValidator passwordValidator13 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator16 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator16;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager15);
    }

    @Test
    public void test817() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test817");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount11 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test818() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test818");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test819() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test819");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator14 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(passwordRuleConf12);
        org.junit.Assert.assertNull(passwordValidator13);
        org.junit.Assert.assertNull(passwordValidator14);
    }

    @Test
    public void test820() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test820");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.entity.user.User user7 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user7, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test821() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test821");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
    }

    @Test
    public void test822() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test822");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator11 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(passwordValidator11);
    }

    @Test
    public void test823() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test823");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
    }

    @Test
    public void test824() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test824");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.passay.PasswordValidator passwordValidator15 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator15;
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test825() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test825");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
    }

    @Test
    public void test826() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test826");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        java.lang.Class<?> wildcardClass12 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNotNull(wildcardClass12);
    }

    @Test
    public void test827() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test827");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf10 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(encryptorManager4);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(passwordRuleConf10);
    }

    @Test
    public void test828() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test828");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test829() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test829");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
    }

    @Test
    public void test830() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test830");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf9 = defaultPasswordRule0.getConf();
        org.passay.PasswordValidator passwordValidator10 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator10;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager12 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager12;
        org.passay.PasswordValidator passwordValidator14 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf15 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf9);
        org.junit.Assert.assertNull(passwordValidator14);
        org.junit.Assert.assertNull(passwordRuleConf15);
    }

    @Test
    public void test831() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test831");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager7);
    }

    @Test
    public void test832() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test832");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(encryptorManager10);
    }

    @Test
    public void test833() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test833");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
        org.junit.Assert.assertNull(encryptorManager10);
    }

    @Test
    public void test834() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test834");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager14;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
    }

    @Test
    public void test835() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test835");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.passay.PasswordValidator passwordValidator14 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator14;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf16 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf16);
    }

    @Test
    public void test836() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test836");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.passay.PasswordValidator passwordValidator13 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNull(passwordValidator13);
    }

    @Test
    public void test837() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test837");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test838() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test838");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
    }

    @Test
    public void test839() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test839");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf6 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf6);
    }

    @Test
    public void test840() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test840");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test841() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test841");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf6);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test842() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test842");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager17 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager17;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf19 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf19);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
    }

    @Test
    public void test843() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test843");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf10 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf12 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(defaultPasswordRuleConf10);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(passwordRuleConf12);
    }

    @Test
    public void test844() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test844");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf13);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(passwordValidator9);
        org.junit.Assert.assertNull(passwordValidator10);
    }

    @Test
    public void test845() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test845");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(encryptorManager7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
    }

    @Test
    public void test846() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test846");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator6;
        org.passay.PasswordValidator passwordValidator8 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator8);
    }

    @Test
    public void test847() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test847");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf7);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
    }

    @Test
    public void test848() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test848");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf13;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
        org.junit.Assert.assertNull(encryptorManager10);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf12);
    }

    @Test
    public void test849() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test849");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager10 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager10;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.core.persistence.api.entity.user.User user14 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(user14, "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
    }

    @Test
    public void test850() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test850");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(encryptorManager9);
    }

    @Test
    public void test851() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test851");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.passay.PasswordValidator passwordValidator8 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator8;
        org.passay.PasswordValidator passwordValidator10 = defaultPasswordRule0.passwordValidator;
        java.lang.String[] strArray15 = new java.lang.String[] { "hi!", "" };
        java.util.LinkedHashSet<java.lang.String> strSet16 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean17 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet16, strArray15);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("", "", (java.util.Set<java.lang.String>) strSet16);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator10);
        org.junit.Assert.assertNotNull(strArray15);
        org.junit.Assert.assertArrayEquals(strArray15, new java.lang.String[] { "hi!", "" });
        org.junit.Assert.assertTrue("'" + boolean17 + "' != '" + true + "'", boolean17 == true);
    }

    @Test
    public void test852() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test852");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf5 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf6 = defaultPasswordRule0.getConf();
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(passwordRuleConf5);
        org.junit.Assert.assertNull(passwordRuleConf6);
    }

    @Test
    public void test853() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test853");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(encryptorManager3);
        org.junit.Assert.assertNull(encryptorManager6);
        org.junit.Assert.assertNull(defaultPasswordRuleConf7);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf9);
    }

    @Test
    public void test854() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test854");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.passay.PasswordValidator passwordValidator11 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(encryptorManager8);
        org.junit.Assert.assertNull(encryptorManager13);
    }

    @Test
    public void test855() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test855");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf2 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf3 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf7 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.entity.user.LinkedAccount linkedAccount8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce(linkedAccount8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf2);
        org.junit.Assert.assertNull(passwordRuleConf7);
    }

    @Test
    public void test856() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test856");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager3 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf7 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf7;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf13 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = defaultPasswordRule0.encryptorManager;
        org.junit.Assert.assertNull(passwordRuleConf13);
        org.junit.Assert.assertNull(encryptorManager14);
    }

    @Test
    public void test857() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test857");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager2 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf8);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
    }

    @Test
    public void test858() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test858");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf11 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf11;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf13 = defaultPasswordRule0.conf;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(defaultPasswordRuleConf13);
    }

    @Test
    public void test859() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test859");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.passay.PasswordValidator passwordValidator4 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf9 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf9;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf11 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf12 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf12;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf14 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = defaultPasswordRule0.encryptorManager;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager16 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager16;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordValidator4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNull(passwordRuleConf11);
        org.junit.Assert.assertNull(defaultPasswordRuleConf14);
        org.junit.Assert.assertNull(encryptorManager15);
    }

    @Test
    public void test860() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test860");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = defaultPasswordRule0.conf;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager5;
        org.passay.PasswordValidator passwordValidator7 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator7;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager11;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager13 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager13;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager15;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf17 = null;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.setConf(passwordRuleConf17);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.PasswordRuleConf.getClass()\" because \"conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf4);
    }

    @Test
    public void test861() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test861");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager5 = defaultPasswordRule0.encryptorManager;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator7 = defaultPasswordRule0.passwordValidator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager8 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager8;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(encryptorManager5);
        org.junit.Assert.assertNull(passwordValidator6);
        org.junit.Assert.assertNull(passwordValidator7);
    }

    @Test
    public void test862() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test862");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager4 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager4;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager6 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager6;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf8 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator9 = defaultPasswordRule0.passwordValidator;
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "hi!");
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf.getWordsNotPermitted()\" because \"this.conf\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf8);
        org.junit.Assert.assertNull(passwordValidator9);
    }

    @Test
    public void test863() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test863");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf2 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator3 = defaultPasswordRule0.passwordValidator;
        org.passay.PasswordValidator passwordValidator4 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator4;
        java.lang.String[] strArray10 = new java.lang.String[] { "", "" };
        java.util.LinkedHashSet<java.lang.String> strSet11 = new java.util.LinkedHashSet<java.lang.String>();
        boolean boolean12 = java.util.Collections.addAll((java.util.Collection<java.lang.String>) strSet11, strArray10);
        // The following exception was thrown during execution in test generation
        try {
            defaultPasswordRule0.enforce("hi!", "", (java.util.Set<java.lang.String>) strSet11);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.passay.PasswordValidator.validate(org.passay.PasswordData)\" because \"this.passwordValidator\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(defaultPasswordRuleConf2);
        org.junit.Assert.assertNull(passwordValidator3);
        org.junit.Assert.assertNotNull(strArray10);
        org.junit.Assert.assertArrayEquals(strArray10, new java.lang.String[] { "", "" });
        org.junit.Assert.assertTrue("'" + boolean12 + "' != '" + true + "'", boolean12 == true);
    }

    @Test
    public void test864() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test864");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf1;
        org.passay.PasswordValidator passwordValidator3 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator3;
        org.passay.PasswordValidator passwordValidator5 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator5;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager7;
    }

    @Test
    public void test865() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test865");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf1 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator2 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator2;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf4 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf5 = defaultPasswordRule0.conf;
        org.passay.PasswordValidator passwordValidator6 = defaultPasswordRule0.passwordValidator;
        org.junit.Assert.assertNull(defaultPasswordRuleConf1);
        org.junit.Assert.assertNull(passwordRuleConf4);
        org.junit.Assert.assertNull(defaultPasswordRuleConf5);
        org.junit.Assert.assertNull(passwordValidator6);
    }

    @Test
    public void test866() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "DefaultPasswordRuleRegression1.test866");
        org.apache.syncope.core.spring.policy.DefaultPasswordRule defaultPasswordRule0 = new org.apache.syncope.core.spring.policy.DefaultPasswordRule();
        org.passay.PasswordValidator passwordValidator1 = null;
        defaultPasswordRule0.passwordValidator = passwordValidator1;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf3 = defaultPasswordRule0.getConf();
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf4 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf4;
        org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf defaultPasswordRuleConf6 = null;
        defaultPasswordRule0.conf = defaultPasswordRuleConf6;
        org.apache.syncope.common.lib.policy.PasswordRuleConf passwordRuleConf8 = defaultPasswordRule0.getConf();
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager9 = null;
        defaultPasswordRule0.encryptorManager = encryptorManager9;
        java.lang.Class<?> wildcardClass11 = defaultPasswordRule0.getClass();
        org.junit.Assert.assertNull(passwordRuleConf3);
        org.junit.Assert.assertNull(passwordRuleConf8);
        org.junit.Assert.assertNotNull(wildcardClass11);
    }
}

