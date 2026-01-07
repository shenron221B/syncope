package org.apache.syncope.core.provisioning.java.utils;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ConnObjectUtilsRegression1 {

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
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test501");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO13 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager14 = connObjectUtils8.encryptorManager;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory15 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils16 = connObjectUtils8.templateUtils;
        org.identityconnectors.framework.common.objects.ConnectorObject connectorObject17 = null;
        org.apache.syncope.common.lib.to.OrgUnit orgUnit18 = null;
        // The following exception was thrown during execution in test generation
        try {
            org.apache.syncope.common.lib.to.RealmTO realmTO19 = connObjectUtils8.getRealmTO(connectorObject17, orgUnit18);
            org.junit.Assert.fail("Expected exception of type java.lang.NullPointerException; message: Cannot invoke \"org.apache.syncope.common.lib.to.OrgUnit.getItems()\" because \"orgUnit\" is null");
        } catch (java.lang.NullPointerException e) {
            // Expected exception.
        }
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(externalResourceDAO13);
        org.junit.Assert.assertNull(encryptorManager14);
        org.junit.Assert.assertNull(anyUtilsFactory15);
        org.junit.Assert.assertNull(templateUtils16);
    }

    @Test
    public void test502() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test502");
        org.identityconnectors.framework.common.objects.Attribute[] attributeArray7 = new org.identityconnectors.framework.common.objects.Attribute[] {};
        java.util.LinkedHashSet<org.identityconnectors.framework.common.objects.Attribute> attributeSet8 = new java.util.LinkedHashSet<org.identityconnectors.framework.common.objects.Attribute>();
        boolean boolean9 = java.util.Collections.addAll((java.util.Collection<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8, attributeArray7);
        org.apache.syncope.common.lib.to.ConnObject connObject10 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("hi!", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject11 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("hi!", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject12 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject13 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("class org.apache.syncope.common.lib.to.ConnObject", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject14 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("100.0", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject15 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("[]", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.apache.syncope.common.lib.to.ConnObject connObject16 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getConnObjectTO("", (java.util.Set<org.identityconnectors.framework.common.objects.Attribute>) attributeSet8);
        org.junit.Assert.assertNotNull(attributeArray7);
        org.junit.Assert.assertArrayEquals(attributeArray7, new org.identityconnectors.framework.common.objects.Attribute[] {});
        org.junit.Assert.assertTrue("'" + boolean9 + "' != '" + false + "'", boolean9 == false);
        org.junit.Assert.assertNotNull(connObject10);
        org.junit.Assert.assertNotNull(connObject11);
        org.junit.Assert.assertNotNull(connObject12);
        org.junit.Assert.assertNotNull(connObject13);
        org.junit.Assert.assertNotNull(connObject14);
        org.junit.Assert.assertNotNull(connObject15);
        org.junit.Assert.assertNotNull(connObject16);
    }

    @Test
    public void test503() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test503");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager13 = connObjectUtils8.mappingManager;
        java.lang.String str14 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getPassword((java.lang.Object) connObjectUtils8);
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO15 = connObjectUtils8.resourceDAO;
        java.lang.String str16 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getPassword((java.lang.Object) connObjectUtils8);
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator17 = connObjectUtils8.passwordGenerator;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(mappingManager13);
        org.junit.Assert.assertNull(externalResourceDAO15);
        org.junit.Assert.assertNull(passwordGenerator17);
    }

    @Test
    public void test504() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test504");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager13 = connObjectUtils8.mappingManager;
        java.lang.String str14 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getPassword((java.lang.Object) connObjectUtils8);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory15 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager16 = connObjectUtils8.mappingManager;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(mappingManager13);
        org.junit.Assert.assertNull(anyUtilsFactory15);
        org.junit.Assert.assertNull(mappingManager16);
    }

    @Test
    public void test505() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test505");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO12 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator13 = connObjectUtils8.passwordGenerator;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(userDAO12);
        org.junit.Assert.assertNull(passwordGenerator13);
    }

    @Test
    public void test506() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test506");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO9 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO10 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO11 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO13 = connObjectUtils8.resourceDAO;
        org.junit.Assert.assertNull(userDAO9);
        org.junit.Assert.assertNull(realmSearchDAO10);
        org.junit.Assert.assertNull(userDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(externalResourceDAO13);
    }

    @Test
    public void test507() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test507");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager13 = connObjectUtils8.mappingManager;
        java.lang.String str14 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getPassword((java.lang.Object) connObjectUtils8);
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO15 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator16 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory17 = connObjectUtils8.anyUtilsFactory;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(mappingManager13);
        org.junit.Assert.assertNull(userDAO15);
        org.junit.Assert.assertNull(passwordGenerator16);
        org.junit.Assert.assertNull(anyUtilsFactory17);
    }

    @Test
    public void test508() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test508");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager10 = connObjectUtils8.mappingManager;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils11 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory12 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator13 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO14 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager15 = connObjectUtils8.mappingManager;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils16 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO17 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator18 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO19 = connObjectUtils8.realmSearchDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(mappingManager10);
        org.junit.Assert.assertNull(templateUtils11);
        org.junit.Assert.assertNull(anyUtilsFactory12);
        org.junit.Assert.assertNull(passwordGenerator13);
        org.junit.Assert.assertNull(realmSearchDAO14);
        org.junit.Assert.assertNull(mappingManager15);
        org.junit.Assert.assertNull(templateUtils16);
        org.junit.Assert.assertNull(realmSearchDAO17);
        org.junit.Assert.assertNull(passwordGenerator18);
        org.junit.Assert.assertNull(realmSearchDAO19);
    }

    @Test
    public void test509() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test509");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager10 = connObjectUtils8.mappingManager;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator11 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils12 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO13 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator14 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager15 = connObjectUtils8.encryptorManager;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO16 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO17 = connObjectUtils8.realmSearchDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(mappingManager10);
        org.junit.Assert.assertNull(passwordGenerator11);
        org.junit.Assert.assertNull(templateUtils12);
        org.junit.Assert.assertNull(userDAO13);
        org.junit.Assert.assertNull(passwordGenerator14);
        org.junit.Assert.assertNull(encryptorManager15);
        org.junit.Assert.assertNull(realmSearchDAO16);
        org.junit.Assert.assertNull(realmSearchDAO17);
    }

    @Test
    public void test510() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test510");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO12 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO13 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO14 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator15 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO16 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO17 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO18 = connObjectUtils8.userDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(userDAO12);
        org.junit.Assert.assertNull(realmSearchDAO13);
        org.junit.Assert.assertNull(userDAO14);
        org.junit.Assert.assertNull(passwordGenerator15);
        org.junit.Assert.assertNull(userDAO16);
        org.junit.Assert.assertNull(realmSearchDAO17);
        org.junit.Assert.assertNull(userDAO18);
    }

    @Test
    public void test511() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test511");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils11 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory12 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO13 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO14 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator15 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO16 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO17 = connObjectUtils8.realmSearchDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(templateUtils11);
        org.junit.Assert.assertNull(anyUtilsFactory12);
        org.junit.Assert.assertNull(userDAO13);
        org.junit.Assert.assertNull(userDAO14);
        org.junit.Assert.assertNull(passwordGenerator15);
        org.junit.Assert.assertNull(externalResourceDAO16);
        org.junit.Assert.assertNull(realmSearchDAO17);
    }

    @Test
    public void test512() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test512");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO12 = connObjectUtils8.resourceDAO;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager13 = connObjectUtils8.mappingManager;
        java.lang.String str14 = org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils.getPassword((java.lang.Object) connObjectUtils8);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory15 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO16 = connObjectUtils8.userDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(externalResourceDAO12);
        org.junit.Assert.assertNull(mappingManager13);
        org.junit.Assert.assertNull(anyUtilsFactory15);
        org.junit.Assert.assertNull(userDAO16);
    }

    @Test
    public void test513() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test513");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO12 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory13 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO14 = connObjectUtils8.userDAO;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator15 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator16 = connObjectUtils8.passwordGenerator;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils17 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils18 = connObjectUtils8.templateUtils;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(userDAO12);
        org.junit.Assert.assertNull(anyUtilsFactory13);
        org.junit.Assert.assertNull(userDAO14);
        org.junit.Assert.assertNull(passwordGenerator15);
        org.junit.Assert.assertNull(passwordGenerator16);
        org.junit.Assert.assertNull(templateUtils17);
        org.junit.Assert.assertNull(templateUtils18);
    }

    @Test
    public void test514() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test514");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils10 = connObjectUtils8.templateUtils;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager11 = connObjectUtils8.encryptorManager;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO12 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO13 = connObjectUtils8.resourceDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(templateUtils10);
        org.junit.Assert.assertNull(encryptorManager11);
        org.junit.Assert.assertNull(realmSearchDAO12);
        org.junit.Assert.assertNull(externalResourceDAO13);
    }

    @Test
    public void test515() throws Throwable {
        if (debug)
            System.out.format("%n%s%n", "ConnObjectUtilsRegression1.test515");
        org.apache.syncope.core.provisioning.java.utils.TemplateUtils templateUtils0 = null;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO1 = null;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO2 = null;
        org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO externalResourceDAO3 = null;
        org.apache.syncope.core.spring.security.PasswordGenerator passwordGenerator4 = null;
        org.apache.syncope.core.provisioning.api.MappingManager mappingManager5 = null;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory6 = null;
        org.apache.syncope.core.persistence.api.EncryptorManager encryptorManager7 = null;
        org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils connObjectUtils8 = new org.apache.syncope.core.provisioning.java.utils.ConnObjectUtils(templateUtils0, realmSearchDAO1, userDAO2, externalResourceDAO3, passwordGenerator4, mappingManager5, anyUtilsFactory6, encryptorManager7);
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory9 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO10 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO11 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO12 = connObjectUtils8.realmSearchDAO;
        org.apache.syncope.core.persistence.api.dao.UserDAO userDAO13 = connObjectUtils8.userDAO;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory14 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory anyUtilsFactory15 = connObjectUtils8.anyUtilsFactory;
        org.apache.syncope.core.persistence.api.dao.RealmSearchDAO realmSearchDAO16 = connObjectUtils8.realmSearchDAO;
        org.junit.Assert.assertNull(anyUtilsFactory9);
        org.junit.Assert.assertNull(userDAO10);
        org.junit.Assert.assertNull(realmSearchDAO11);
        org.junit.Assert.assertNull(realmSearchDAO12);
        org.junit.Assert.assertNull(userDAO13);
        org.junit.Assert.assertNull(anyUtilsFactory14);
        org.junit.Assert.assertNull(anyUtilsFactory15);
        org.junit.Assert.assertNull(realmSearchDAO16);
    }
}

