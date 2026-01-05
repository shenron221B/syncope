package org.apache.syncope.core.spring.policy;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.policy.PasswordRuleConf;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.passay.PasswordValidator;
import org.passay.RuleResult;

@ExtendWith(MockitoExtension.class)
class DefaultPasswordRuleZeroShotLLMTest {

    @Spy
    @InjectMocks
    private DefaultPasswordRule rule;

    @Mock
    private PasswordValidator passwordValidator;

    @Mock
    private RuleResult ruleResult;

    private DefaultPasswordRuleConf validConf;

    @BeforeEach
    void setUp() {
        validConf = new DefaultPasswordRuleConf();
        validConf.setMinLength(8);
        validConf.setMaxLength(20);
        validConf.setUppercase(1);
        validConf.setLowercase(1);
        validConf.setDigit(1);
        validConf.setSpecial(0);
        validConf.setUsernameAllowed(true);
        validConf.getWordsNotPermitted().add("forbidden");
    }

    // ---------------------------------------------------------------------
    // setConf tests
    // ---------------------------------------------------------------------

    @Test
    void setConf_shouldAcceptDefaultPasswordRuleConf() {
        assertDoesNotThrow(() -> rule.setConf(validConf));
        assertNotNull(rule.getConf());
        assertEquals(validConf, rule.getConf());
    }

    @Test
    void setConf_shouldRejectNonDefaultPasswordRuleConf() {
        PasswordRuleConf wrongConf = mock(PasswordRuleConf.class);

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> rule.setConf(wrongConf));

        assertTrue(ex.getMessage().contains(DefaultPasswordRuleConf.class.getName()));
    }

    // ---------------------------------------------------------------------
    // enforce(String, String) tests
    // ---------------------------------------------------------------------

    @Test
    void enforce_shouldDoNothing_whenPasswordIsNull() {
        rule.setConf(validConf);

        assertDoesNotThrow(() -> rule.enforce("user1", null));
        verifyNoInteractions(passwordValidator);
    }

    @Test
    void enforce_shouldPass_whenPasswordIsValid_andNoForbiddenWords() {
        rule.setConf(validConf);
        rule.passwordValidator = passwordValidator;

        when(passwordValidator.validate(any()))
                .thenReturn(ruleResult);
        when(ruleResult.isValid())
                .thenReturn(true);

        assertDoesNotThrow(() -> rule.enforce("user1", "ValidPass1"));

        verify(passwordValidator).validate(any());
        verify(ruleResult).isValid();
    }

    @Test
    void enforce_shouldFail_whenPassayValidationFails() {
        rule.setConf(validConf);
        rule.passwordValidator = passwordValidator;

        when(passwordValidator.validate(any()))
                .thenReturn(ruleResult);
        when(ruleResult.isValid())
                .thenReturn(false);
        when(passwordValidator.getMessages(ruleResult))
                .thenReturn(List.of("TOO_SHORT"));

        PasswordPolicyException ex = assertThrows(
                PasswordPolicyException.class,
                () -> rule.enforce("user1", "bad"));

        assertTrue(ex.getMessage().contains("TOO_SHORT"));
    }

    @Test
    void enforce_shouldFail_whenPasswordContainsForbiddenWord() {
        rule.setConf(validConf);
        rule.passwordValidator = passwordValidator;

        when(passwordValidator.validate(any()))
                .thenReturn(ruleResult);
        when(ruleResult.isValid())
                .thenReturn(true);

        PasswordPolicyException ex = assertThrows(
                PasswordPolicyException.class,
                () -> rule.enforce("user1", "MyForbiddenPassword1"));

        assertEquals("Used word(s) not permitted", ex.getMessage());
    }

    @Test
    void enforce_shouldBeCaseInsensitive_whenCheckingForbiddenWords() {
        rule.setConf(validConf);
        rule.passwordValidator = passwordValidator;

        when(passwordValidator.validate(any()))
                .thenReturn(ruleResult);
        when(ruleResult.isValid())
                .thenReturn(true);

        PasswordPolicyException ex = assertThrows(
                PasswordPolicyException.class,
                () -> rule.enforce("user1", "myFoRbIdDeNpAss1"));

        assertEquals("Used word(s) not permitted", ex.getMessage());
    }
}
