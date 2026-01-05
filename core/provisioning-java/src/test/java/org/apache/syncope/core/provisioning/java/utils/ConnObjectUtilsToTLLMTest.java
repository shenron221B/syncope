package org.apache.syncope.core.provisioning.java.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.ArrayList;
import java.util.Optional;

import org.apache.syncope.common.lib.request.*;
import org.apache.syncope.common.lib.to.*;
import org.apache.syncope.common.lib.types.AnyTypeKind;
import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.persistence.api.Encryptor;
import org.apache.syncope.core.persistence.api.EncryptorManager;
import org.apache.syncope.core.persistence.api.dao.ExternalResourceDAO;
import org.apache.syncope.core.persistence.api.dao.RealmSearchDAO;
import org.apache.syncope.core.persistence.api.dao.UserDAO;
import org.apache.syncope.core.persistence.api.entity.AnyUtils;
import org.apache.syncope.core.persistence.api.entity.AnyUtilsFactory;
import org.apache.syncope.core.persistence.api.entity.Realm;
import org.apache.syncope.core.persistence.api.entity.task.InboundTask;
import org.apache.syncope.core.persistence.api.entity.user.User;
import org.apache.syncope.core.provisioning.api.MappingManager;
import org.apache.syncope.core.spring.security.PasswordGenerator;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ConnObjectUtilsToTLLMTest {

    @Mock
    private TemplateUtils templateUtils;

    @Mock
    private RealmSearchDAO realmSearchDAO;

    @Mock
    private UserDAO userDAO;

    @Mock
    private ExternalResourceDAO resourceDAO;

    @Mock
    private PasswordGenerator passwordGenerator;

    @Mock
    private MappingManager mappingManager;

    @Mock
    private AnyUtilsFactory anyUtilsFactory;

    @Mock
    private EncryptorManager encryptorManager;

    @Mock
    private AnyUtils anyUtils;

    @InjectMocks
    private ConnObjectUtils utils;

    @Mock
    private InboundTask<?> inboundTask;

    @Mock
    private ConnectorObject connectorObject;

    @Mock
    private Provision provision;

    @BeforeEach
    void setup() {
        when(anyUtilsFactory.getInstance(any(AnyTypeKind.class))).thenReturn(anyUtils);

        Realm destinationRealm = mock(Realm.class);
        when(destinationRealm.getFullPath()).thenReturn("/");
        when(inboundTask.getDestinationRealm()).thenReturn(destinationRealm);

        when(provision.getAuxClasses()).thenReturn(new ArrayList<>());
        when(provision.getMapping()).thenReturn(new Mapping());
    }

    @Test
    void testGetAnyCR_UserPasswordGenerated() {
        when(provision.getAnyType()).thenReturn("USER");

        UserCR userCR = new UserCR();
        UserTO userTO = new UserTO();

        when(anyUtils.newAnyCR()).thenReturn(userCR);
        when(anyUtils.newAnyTO()).thenReturn(userTO);
        when(passwordGenerator.generate(anyList())).thenReturn("generatedPwd");
        when(realmSearchDAO.findByFullPath(anyString())).thenReturn(Optional.empty());

        UserCR result = utils.getAnyCR(
                connectorObject,
                inboundTask,
                AnyTypeKind.USER,
                provision,
                true);

        assertNotNull(result);
        assertEquals("generatedPwd", result.getPassword());
    }

    @Test
    void testGetAnyCR_UserPasswordAlreadySet_NoGeneration() {
        when(provision.getAnyType()).thenReturn("USER");

        UserCR userCR = new UserCR();
        userCR.setPassword("existing");

        when(anyUtils.newAnyCR()).thenReturn(userCR);
        when(anyUtils.newAnyTO()).thenReturn(new UserTO());

        UserCR result = utils.getAnyCR(
                connectorObject,
                inboundTask,
                AnyTypeKind.USER,
                provision,
                false); // 🔑 generation disabled

        assertNull(result.getPassword());
        verify(passwordGenerator, never()).generate(anyList());
    }

    @Test
    void testGetAnyUR_UserPasswordUnchangedCleared() {
        when(provision.getAnyType()).thenReturn("USER");

        UserTO original = new UserTO();
        original.setKey("1");
        original.setUsername("orig");

        UserTO updated = new UserTO();
        updated.setPassword("same");

        when(anyUtils.newAnyTO()).thenReturn(updated);

        User userEntity = mock(User.class);
        when(userEntity.getCipherAlgorithm()).thenReturn(CipherAlgorithm.SHA256);
        when(userEntity.getPassword()).thenReturn("encrypted");

        when(userDAO.authFind("1")).thenReturn(userEntity);

        Encryptor encryptor = mock(Encryptor.class);
        when(encryptorManager.getInstance()).thenReturn(encryptor);
        when(encryptor.verify(anyString(), any(CipherAlgorithm.class), anyString()))
                .thenReturn(true);

        UserUR result = utils.getAnyUR(
                "1",
                connectorObject,
                original,
                inboundTask,
                AnyTypeKind.USER,
                provision);

        assertNotNull(result);
        assertNull(result.getRealm());
    }

    @Test
    void testGetAnyUR_GroupNameFallback() {
        when(provision.getAnyType()).thenReturn("GROUP");

        GroupTO original = new GroupTO();
        original.setKey("g");
        original.setName("group");

        when(anyUtils.newAnyTO()).thenReturn(new GroupTO());

        GroupUR result = utils.getAnyUR(
                "g",
                connectorObject,
                original,
                inboundTask,
                AnyTypeKind.GROUP,
                provision);

        assertNotNull(result);
        assertNull(result.getRealm());
    }

    @Test
    void testGetAnyUR_AnyObjectNameFallback() {
        when(provision.getAnyType()).thenReturn("PRINTER");

        AnyObjectTO original = new AnyObjectTO();
        original.setKey("a");
        original.setName("obj");

        when(anyUtils.newAnyTO()).thenReturn(new AnyObjectTO());

        AnyObjectUR result = utils.getAnyUR(
                "a",
                connectorObject,
                original,
                inboundTask,
                AnyTypeKind.ANY_OBJECT,
                provision);

        assertNotNull(result);
        assertNull(result.getRealm());
    }
}
