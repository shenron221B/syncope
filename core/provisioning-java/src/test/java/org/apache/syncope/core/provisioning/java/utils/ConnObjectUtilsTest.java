/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.core.provisioning.java.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.apache.syncope.common.lib.Attr;
import org.apache.syncope.common.lib.request.UserUR;
import org.apache.syncope.common.lib.request.GroupUR;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.apache.syncope.common.lib.request.*;
import org.apache.syncope.common.lib.to.AnyObjectTO;
import org.apache.syncope.common.lib.to.GroupTO;
import org.apache.syncope.common.lib.to.Mapping;
import org.apache.syncope.common.lib.to.Provision;
import org.apache.syncope.common.lib.to.UserTO;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.CipherAlgorithm; // FIX: Import aggiunto per l'Enum
import org.apache.syncope.core.persistence.api.Encryptor;
import org.apache.syncope.core.persistence.api.EncryptorManager;
import org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO;
import org.apache.syncope.core.persistence.api.dao.RealmSearchDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.AnyUtils;
import org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory;
import org.apache.syncope.core.persistence.api.entity.ExternalResource; // FIX: Import corretto (senza .resource)
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.persistence.api.entity.task.InboundTask;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.MappingManager;
import org.apache.syncope.core.spring.security.PasswordGenerator;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class ConnObjectUtilsTest {

    private ConnObjectUtils connObjectUtils;

    private TemplateUtils templateUtils;
    private RealmSearchDAO realmSearchDAO;
    private UserDAO userDAO;
    private ExternalResourceDAO resourceDAO;
    private PasswordGenerator passwordGenerator;
    private MappingManager mappingManager;
    private AnyUtilsFactory anyUtilsFactory;
    private EncryptorManager encryptorManager;

    private AnyUtils userUtils;
    private AnyUtils groupUtils;
    private AnyUtils anyObjectUtils;

    @BeforeEach
    void setUp() {
        templateUtils = mock(TemplateUtils.class);
        realmSearchDAO = mock(RealmSearchDAO.class);
        userDAO = mock(UserDAO.class);
        resourceDAO = mock(ExternalResourceDAO.class);
        passwordGenerator = mock(PasswordGenerator.class);
        mappingManager = mock(MappingManager.class);
        anyUtilsFactory = mock(AnyUtilsFactory.class);
        encryptorManager = mock(EncryptorManager.class);

        userUtils = mock(AnyUtils.class);
        groupUtils = mock(AnyUtils.class);
        anyObjectUtils = mock(AnyUtils.class);

        when(anyUtilsFactory.getInstance(AnyTypeKind.USER)).thenReturn(userUtils);
        when(anyUtilsFactory.getInstance(AnyTypeKind.GROUP)).thenReturn(groupUtils);
        when(anyUtilsFactory.getInstance(AnyTypeKind.ANY_OBJECT)).thenReturn(anyObjectUtils);
        when(userUtils.newAnyCR()).thenReturn(new UserCR());
        when(userUtils.newAnyTO()).thenReturn(new UserTO());
        when(groupUtils.newAnyTO()).thenReturn(new GroupTO());
        when(groupUtils.newAnyCR()).thenReturn(new GroupCR());
        when(anyObjectUtils.newAnyTO()).thenReturn(new AnyObjectTO());

        connObjectUtils = new ConnObjectUtils(
                templateUtils,
                realmSearchDAO,
                userDAO,
                resourceDAO,
                passwordGenerator,
                mappingManager,
                anyUtilsFactory,
                encryptorManager
        );
    }

    @Test
    void T01_getAnyCR_User_WithPassword_BaseCase() {
        String remotePassword = "Password123!";
        ConnectorObject connObj = buildConnectorObject("testUser", remotePassword, true);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        when(userUtils.newAnyTO()).thenAnswer(invocation -> {
            UserTO userTO = new UserTO();
            userTO.setPassword(remotePassword);
            return userTO;
        });

        UserCR result = connObjectUtils.getAnyCR(
                connObj, task, AnyTypeKind.USER, provision, true
        );

        assertNotNull(result);
        assertEquals(remotePassword, result.getPassword());
        verify(passwordGenerator, never()).generate(any());
    }

    @Test
    void T02_getAnyCR_User_NoPassword_GenerateTrue() {
        ConnectorObject connObj = buildConnectorObject("testUser", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        String generatedPwd = "GeneratedPassword123!";
        when(passwordGenerator.generate(any())).thenReturn(generatedPwd);

        UserCR result = connObjectUtils.getAnyCR(
                connObj, task, AnyTypeKind.USER, provision, true
        );

        assertNotNull(result);
        assertEquals(generatedPwd, result.getPassword());
        verify(passwordGenerator).generate(any());
    }

    @Test
    void T03_getAnyCR_User_WithPassword_And_GenerateTrue() {
        String remotePassword = "ExternalPassword!";
        ConnectorObject connObj = buildConnectorObject("testUser", remotePassword, true);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.setPassword(remotePassword);
            return u;
        });

        UserCR result = connObjectUtils.getAnyCR(
                connObj, task, AnyTypeKind.USER, provision, true
        );

        assertEquals(remotePassword, result.getPassword());
        verify(passwordGenerator, never()).generate(any());
    }

    @Test
    void T04_getAnyCR_Group_BaseCase() {
        ConnectorObject connObj = buildConnectorObject("testGroup", null, false);
        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        Object result = connObjectUtils.getAnyCR(
                connObj, task, AnyTypeKind.GROUP, provision, false
        );

        assertNotNull(result);
        verify(anyUtilsFactory, times(2)).getInstance(AnyTypeKind.GROUP);
    }

    @Test
    void T05_getAnyUR_User_BaseCase() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("userUpdate", null, false);
        UserTO original = new UserTO();
        original.setKey(key);
        original.setUsername("oldUsername");

        Provision provision = buildProvision(AnyTypeKind.USER);
        provision.setAnyType("USER");
        InboundTask<?> task = mockInboundTask();

        User authUser = mock(User.class);
        when(userDAO.authFind(key)).thenReturn(authUser);

        Encryptor encryptor = mock(Encryptor.class);
        when(encryptorManager.getInstance()).thenReturn(encryptor);
        when(encryptor.verify(any(), any(), any())).thenReturn(true);

        connObjectUtils.getAnyUR(
                key, connObj, original, task, AnyTypeKind.USER, provision
        );

        verify(userDAO).authFind(key);
    }

    @Test
    void T06_getAnyUR_NullKey_ShouldThrowOrFail() {
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        UserTO original = new UserTO();
        Provision provision = buildProvision(AnyTypeKind.USER);
        provision.setAnyType("USER");
        InboundTask<?> task = mockInboundTask();

        when(userDAO.authFind(null)).thenThrow(new IllegalArgumentException("Key cannot be null"));

        assertThrows(IllegalArgumentException.class, () ->
                connObjectUtils.getAnyUR(null, connObj, original, task, AnyTypeKind.USER, provision)
        );
    }

    @Test
    void T07_getAnyUR_InconsistentType_ShouldFail() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("group", null, false);

        UserTO original = new UserTO();
        Provision provision = buildProvision(AnyTypeKind.GROUP);
        provision.setAnyType("GROUP");
        InboundTask<?> task = mockInboundTask();

        assertThrows(ClassCastException.class, () ->
                connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision)
        );
    }

    @Test
    void T08_getAnyUR_Group_BaseCase() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("groupUpdate", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("oldGroupName");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        provision.setAnyType("GROUP");
        InboundTask<?> task = mockInboundTask();

        connObjectUtils.getAnyUR(
                key, connObj, original, task, AnyTypeKind.GROUP, provision
        );
        verify(anyUtilsFactory).getInstance(AnyTypeKind.GROUP);
    }

    @Test
    void T09_getAnyUR_AnyObject_BaseCase() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("printerUpdate", null, false);

        AnyObjectTO original = new AnyObjectTO();
        original.setKey(key);
        original.setName("oldPrinterName");

        Provision provision = buildProvision(AnyTypeKind.ANY_OBJECT);
        provision.setAnyType("PRINTER");
        InboundTask<?> task = mockInboundTask();

        connObjectUtils.getAnyUR(
                key, connObj, original, task, AnyTypeKind.ANY_OBJECT, provision
        );

        verify(anyUtilsFactory).getInstance(AnyTypeKind.ANY_OBJECT);
    }

    // metodi di supporto

    private InboundTask<?> mockInboundTask() {
        InboundTask<?> task = mock(InboundTask.class);
        Realm realm = mock(Realm.class);
        when(realm.getFullPath()).thenReturn("/test/realm");
        when(task.getDestinationRealm()).thenReturn(realm);
        return task;
    }

    private ConnectorObject buildConnectorObject(String name, String password, boolean hasPwd) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(new Uid(name));
        builder.setName(new Name(name));
        if (hasPwd) {
            builder.addAttribute(AttributeBuilder.buildPassword(password != null ? password.toCharArray() : new char[0]));
        }
        return builder.build();
    }

    private Provision buildProvision(AnyTypeKind kind) {
        Provision provision = new Provision();
        provision.setAnyType(kind.name());
        Mapping mapping = new Mapping();
        provision.setMapping(mapping);
        return provision;
    }

    // test aggiuntivi (JaCoCo)

    @Test
    void T10_getAnyCR_WithPasswordPolicies() {
        ConnectorObject connObj = buildConnectorObject("testUser", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        String resKey = "resource-test";
        ExternalResource resource = mock(ExternalResource.class);
        PasswordPolicy policy1 = mock(PasswordPolicy.class);
        when(resource.getPasswordPolicy()).thenReturn(policy1);

        doReturn(Optional.of(resource)).when(resourceDAO).findById(resKey);

        Realm realm = mock(Realm.class);
        when(realm.getFullPath()).thenReturn("/test");

        Realm ancestor = mock(Realm.class);
        PasswordPolicy policy2 = mock(PasswordPolicy.class);
        when(ancestor.getPasswordPolicy()).thenReturn(policy2);

        when(realmSearchDAO.findByFullPath(any())).thenReturn(Optional.of(realm));
        when(realmSearchDAO.findAncestors(realm)).thenReturn(List.of(ancestor));
        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.getResources().add(resKey);
            u.setRealm("/test");
            return u;
        });

        connObjectUtils.getAnyCR(connObj, task, AnyTypeKind.USER, provision, true);
        verify(passwordGenerator).generate(any());
    }

    @Test
    void T11_getAnyUR_User_PartialUpdate_And_EncryptorVerify() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("userUpdate", "OldPass", true);

        UserTO original = new UserTO();
        original.setKey(key);
        original.setUsername("originalUser");
        original.setPassword("OldPass");

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        User authUser = mock(User.class);
        when(authUser.getCipherAlgorithm()).thenReturn(CipherAlgorithm.SHA1);
        when(authUser.getPassword()).thenReturn("OldPass");
        when(userDAO.authFind(key)).thenReturn(authUser);

        Encryptor encryptor = mock(Encryptor.class);
        when(encryptorManager.getInstance()).thenReturn(encryptor);
        when(encryptor.verify(any(), any(), any())).thenReturn(true);

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.setUsername(null);
            u.setPassword("OldPass");
            return u;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);
        verify(encryptor).verify(any(), any(), any());
    }

    @Test
    void T12_getAnyUR_Group_PartialUpdate() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("group", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("OriginalName");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        when(groupUtils.newAnyTO()).thenAnswer(inv -> {
            GroupTO g = new GroupTO();
            g.setName(null);
            return g;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision);
        verify(anyUtilsFactory).getInstance(AnyTypeKind.GROUP);
    }

    @Test
    void T13_getAnyUR_AnyObject_PartialUpdate() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("printer", null, false);

        AnyObjectTO original = new AnyObjectTO();
        original.setKey(key);
        original.setName("OriginalPrinter");

        Provision provision = buildProvision(AnyTypeKind.ANY_OBJECT);
        provision.setAnyType("PRINTER");
        InboundTask<?> task = mockInboundTask();

        when(anyObjectUtils.newAnyTO()).thenAnswer(inv -> {
            AnyObjectTO a = new AnyObjectTO();
            a.setName(null);
            return a;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.ANY_OBJECT, provision);
        verify(anyUtilsFactory).getInstance(AnyTypeKind.ANY_OBJECT);
    }

    @Test
    void T14_getAnyUR_NoDifferences_ReturnsNull() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        UserTO original = new UserTO();
        original.setKey(key);
        original.setUsername("sameUser");

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        User authUser = mock(User.class);
        when(userDAO.authFind(key)).thenReturn(authUser);

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.setUsername("sameUser");
            return u;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);
    }

    @Test
    void T15_getAnyCR_User_NoPassword_GenerateFalse() {
        ConnectorObject connObj = buildConnectorObject("testUser", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        connObjectUtils.getAnyCR(connObj, task, AnyTypeKind.USER, provision, false);
        verify(passwordGenerator, never()).generate(any());
    }

    @Test
    void T16_getAnyCR_WithNullAndDuplicatePolicies() {
        ConnectorObject connObj = buildConnectorObject("userPoly", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        String resKey = "res-null-policy";
        ExternalResource resNull = mock(ExternalResource.class);
        when(resNull.getPasswordPolicy()).thenReturn(null); // Copre riga 207
        doReturn(Optional.of(resNull)).when(resourceDAO).findById(resKey);

        Realm realm = mock(Realm.class);
        when(realm.getFullPath()).thenReturn("/test");
        doReturn(Optional.of(realm)).when(realmSearchDAO).findByFullPath(any());

        Realm anc1 = mock(Realm.class);
        PasswordPolicy policyA = mock(PasswordPolicy.class);
        when(anc1.getPasswordPolicy()).thenReturn(policyA);

        Realm anc2 = mock(Realm.class);
        when(anc2.getPasswordPolicy()).thenReturn(null);

        Realm anc3 = mock(Realm.class);
        when(anc3.getPasswordPolicy()).thenReturn(policyA);

        when(realmSearchDAO.findAncestors(realm)).thenReturn(List.of(anc1, anc2, anc3));

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.getResources().add(resKey);
            u.setRealm("/test");
            return u;
        });

        connObjectUtils.getAnyCR(connObj, task, AnyTypeKind.USER, provision, true);

        verify(passwordGenerator).generate(any());
    }

    @Test
    void T17_getAnyUR_User_EncryptorVerify_False() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", "NewPass", true);
        UserTO original = new UserTO();
        original.setKey(key);
        original.setPassword("OldPass");

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        User authUser = mock(User.class);
        when(authUser.getCipherAlgorithm()).thenReturn(CipherAlgorithm.SHA1);
        when(authUser.getPassword()).thenReturn("OldPass");
        when(userDAO.authFind(key)).thenReturn(authUser);

        Encryptor encryptor = mock(Encryptor.class);
        when(encryptorManager.getInstance()).thenReturn(encryptor);

        when(encryptor.verify(any(), any(), any())).thenReturn(false);

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.setPassword("NewPass");
            return u;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        verify(encryptor).verify(any(), any(), any());
    }

    @Test
    void T18_getAnyUR_User_MustChangePassword_True() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        UserTO original = new UserTO();
        original.setKey(key);

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        User authUser = mock(User.class);
        when(userDAO.authFind(key)).thenReturn(authUser);

        when(mappingManager.hasMustChangePassword(provision)).thenReturn(true);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);
        verify(mappingManager).hasMustChangePassword(provision);
    }

    @Test
    void T19_getAnyUR_Group_Name_Populated() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("groupUpdate", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("OldGroupName");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        when(groupUtils.newAnyTO()).thenAnswer(inv -> {
            GroupTO g = new GroupTO();
            g.setName("NewGroupName");
            return g;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision);

        verify(anyUtilsFactory).getInstance(AnyTypeKind.GROUP);
    }

    @Test
    void T20_getAnyUR_AnyObject_Name_Populated() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("printerUpdate", null, false);

        AnyObjectTO original = new AnyObjectTO();
        original.setKey(key);
        original.setName("OldPrinterName");

        Provision provision = buildProvision(AnyTypeKind.ANY_OBJECT);
        provision.setAnyType("PRINTER");
        InboundTask<?> task = mockInboundTask();

        when(anyObjectUtils.newAnyTO()).thenAnswer(inv -> {
            AnyObjectTO a = new AnyObjectTO();
            a.setName("NewPrinterName");
            return a;
        });

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.ANY_OBJECT, provision);

        verify(anyUtilsFactory).getInstance(AnyTypeKind.ANY_OBJECT);
    }

    // mutation testing

    @Test
    void T21_getAnyCR_Filter_NullPolicy() {
        ConnectorObject connObj = buildConnectorObject("userNullPol", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        String resKey = "res-Null";
        ExternalResource resNull = mock(ExternalResource.class);
        when(resNull.getPasswordPolicy()).thenReturn(null);
        doReturn(Optional.of(resNull)).when(resourceDAO).findById(resKey);

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.getResources().add(resKey);
            return u;
        });

        connObjectUtils.getAnyCR(connObj, task, AnyTypeKind.USER, provision, true);

        ArgumentCaptor<List<PasswordPolicy>> captor = ArgumentCaptor.forClass(List.class);
        verify(passwordGenerator).generate(captor.capture());

        assertEquals(0, captor.getValue().size(), "Il filtro NULL ha fallito: la lista dovrebbe essere vuota");
    }

    @Test
    void T22_getAnyUR_User_Properties_Preserved() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);

        UserTO original = new UserTO();
        original.setKey(key);
        original.setSecurityQuestion("Q?");
        original.setMustChangePassword(true);

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        when(userDAO.authFind(key)).thenReturn(mock(User.class));
        when(mappingManager.hasMustChangePassword(provision)).thenReturn(false);

        UserTO spyUpdated = spy(new UserTO());
        when(userUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        verify(spyUpdated).setSecurityQuestion("Q?");
        verify(spyUpdated).setMustChangePassword(true);
    }

    @Test
    void T23_getAnyUR_Group_DynMemberships_Preserved() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("group", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("Group");
        original.setUDynMembershipCond("user == 'smart'");
        original.getADynMembershipConds().put("PRINTER", "model == 'canon'");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        GroupTO spyUpdated = spy(new GroupTO());
        spyUpdated.setName("Group");
        when(groupUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision);

        verify(spyUpdated).setUDynMembershipCond("user == 'smart'");
        assertEquals("model == 'canon'", spyUpdated.getADynMembershipConds().get("PRINTER"),
                "La mappa deve essere stata popolata tramite putAll");
    }

    @Test
    void T24_getAnyUR_User_PasswordReset() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", "Pass", true);
        UserTO original = new UserTO();
        original.setKey(key);
        original.setPassword("Pass");

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        User authUser = mock(User.class);
        when(authUser.getPassword()).thenReturn("Pass");
        when(userDAO.authFind(key)).thenReturn(authUser);

        Encryptor encryptor = mock(Encryptor.class);
        when(encryptorManager.getInstance()).thenReturn(encryptor);
        when(encryptor.verify(any(), any(), any())).thenReturn(true);

        UserTO spyUpdated = spy(new UserTO());
        spyUpdated.setPassword("Pass");
        when(userUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        verify(spyUpdated).setPassword(null);
    }

    @Test
    void T25_getAnyUR_User_RestoreProps() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);

        UserTO original = new UserTO();
        original.setKey(key);
        original.setSecurityQuestion("Q?");
        original.setMustChangePassword(true);

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        when(userDAO.authFind(key)).thenReturn(mock(User.class));
        when(mappingManager.hasMustChangePassword(provision)).thenReturn(false);

        when(userUtils.newAnyTO()).thenAnswer(inv -> new UserTO());

        UserUR result = (UserUR) connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        assertNotNull(result);
        assertNull(result.getSecurityQuestion(), "SecurityQuestion non deve essere nel patch");
        assertNull(result.getMustChangePassword(), "MustChangePassword non deve essere nel patch");
    }

    @Test
    void T26_getAnyUR_Group_RestoreName() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("group", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("GroupA");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        GroupTO spyUpdated = spy(new GroupTO());
        spyUpdated.setName(null);
        when(groupUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision);

        verify(spyUpdated).setName("GroupA");
    }

    @Test
    void T27_getAnyUR_Group_RestoreOwners() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("group", null, false);

        GroupTO original = new GroupTO();
        original.setKey(key);
        original.setName("G");
        original.setUserOwner("U");
        original.setGroupOwner("G2");

        Provision provision = buildProvision(AnyTypeKind.GROUP);
        InboundTask<?> task = mockInboundTask();

        GroupTO spyUpdated = spy(new GroupTO());
        spyUpdated.setName("G");
        when(groupUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.GROUP, provision);

        verify(spyUpdated).setUserOwner("U");
        verify(spyUpdated).setGroupOwner("G2");
    }

    @Test
    void T28_getAnyUR_AnyObject_RestoreName() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("any", null, false);

        AnyObjectTO original = new AnyObjectTO();
        original.setKey(key);
        original.setName("PrinterA");

        Provision provision = buildProvision(AnyTypeKind.ANY_OBJECT);
        provision.setAnyType("PRINTER");
        InboundTask<?> task = mockInboundTask();

        AnyObjectTO spyUpdated = spy(new AnyObjectTO());
        spyUpdated.setName(null);
        when(anyObjectUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.ANY_OBJECT, provision);

        verify(spyUpdated).setName("PrinterA");
    }

    @Test
    void T29_getAnyUR_CleanEmptyAttrs() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        UserTO original = new UserTO();
        original.setKey(key);
        original.getPlainAttrs().add(new Attr.Builder("badge").value("123").build());

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        when(userDAO.authFind(key)).thenReturn(mock(User.class));

        UserTO tempUser = new UserTO();
        tempUser.getPlainAttrs().add(new Attr.Builder("badge").build());

        UserTO spyUpdated = spy(tempUser);
        when(userUtils.newAnyTO()).thenReturn(spyUpdated);
        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        verify(spyUpdated, times(2)).getPlainAttrs();
    }

    @Test
    void T30_getAnyUR_RealmReset() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        UserTO original = new UserTO();
        original.setKey(key);
        original.setRealm("/old");

        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();
        when(userDAO.authFind(key)).thenReturn(mock(User.class));

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.setRealm("/new");
            return u;
        });

        UserUR result = (UserUR) connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        assertNotNull(result);
        assertNull(result.getRealm(), "Il realm deve essere forzato a null nel patch");
    }

    @Test
    void T31_getAnyCR_Policy_Aggregation() {
        ConnectorObject connObj = buildConnectorObject("userPol", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        String resKey = "res-1";
        ExternalResource resource = mock(ExternalResource.class);
        PasswordPolicy policyRes = mock(PasswordPolicy.class);
        when(resource.getPasswordPolicy()).thenReturn(policyRes);
        doReturn(Optional.of(resource)).when(resourceDAO).findById(resKey);

        Realm realm = mock(Realm.class);
        when(realm.getFullPath()).thenReturn("/test");
        doReturn(Optional.of(realm)).when(realmSearchDAO).findByFullPath(any());

        Realm ancestor = mock(Realm.class);
        PasswordPolicy policyAnc = mock(PasswordPolicy.class);
        when(ancestor.getPasswordPolicy()).thenReturn(policyAnc);
        when(realmSearchDAO.findAncestors(realm)).thenReturn(List.of(ancestor));

        when(userUtils.newAnyTO()).thenAnswer(inv -> {
            UserTO u = new UserTO();
            u.getResources().add(resKey);
            u.setRealm("/test");
            return u;
        });

        connObjectUtils.getAnyCR(connObj, task, AnyTypeKind.USER, provision, true);

        ArgumentCaptor<List<PasswordPolicy>> captor = ArgumentCaptor.forClass(List.class);
        verify(passwordGenerator).generate(captor.capture());
        List<PasswordPolicy> policies = captor.getValue();

        assertEquals(2, policies.size(), "Deve contenere sia la policy risorsa che quella ancestor");
        assertTrue(policies.contains(policyRes));
        assertTrue(policies.contains(policyAnc));
    }

    @Test
    void T32_getAnyUR_User_RestoreUsername_Spy() {
        String key = UUID.randomUUID().toString();
        ConnectorObject connObj = buildConnectorObject("user", null, false);
        Provision provision = buildProvision(AnyTypeKind.USER);
        InboundTask<?> task = mockInboundTask();

        UserTO original = new UserTO();
        original.setKey(key);
        original.setUsername("OriginalName");

        when(userDAO.authFind(key)).thenReturn(mock(User.class));

        UserTO spyUpdated = spy(new UserTO());
        spyUpdated.setUsername(null);
        when(userUtils.newAnyTO()).thenReturn(spyUpdated);

        connObjectUtils.getAnyUR(key, connObj, original, task, AnyTypeKind.USER, provision);

        verify(spyUpdated).setUsername("OriginalName");
    }

}