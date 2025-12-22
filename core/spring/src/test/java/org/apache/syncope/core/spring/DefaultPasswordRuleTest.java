package org.apache.syncope.core.spring;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.common.lib.policy.PasswordRuleConf;
import org.apache.syncope.core.spring.policy.DefaultPasswordRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DefaultPasswordRuleTest {

    private DefaultPasswordRule rule;
    private DefaultPasswordRuleConf conf;

    @BeforeEach
    void setUp() {
        rule = new DefaultPasswordRule();
        conf = new DefaultPasswordRuleConf();
        conf.setMinLength(0);
        conf.setMaxLength(1000);
        conf.setAlphabetical(0);
        conf.setUppercase(0);
        conf.setLowercase(0);
        conf.setDigit(0);
        conf.setSpecial(0);
        conf.setUsernameAllowed(true);
    }

    @Test
    void T01_testSetConf_ValidInstance() {
        assertDoesNotThrow(() -> rule.setConf(conf));
    }

    @Test
    void T02_testSetConf_InvalidInstance() {
        PasswordRuleConf invalidConf = mock(PasswordRuleConf.class);
        assertThrows(IllegalArgumentException.class, () -> rule.setConf(invalidConf));
    }

    @Test
    void T03_testEnforce_NullPassword_SafeExit() {
        rule.setConf(conf);
        assertDoesNotThrow(() -> rule.enforce("username", null));
    }

    @Test
    void T04_testEnforce_MinLength_Boundary() {
        conf.setMinLength(8);
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "1234567"));

        assertDoesNotThrow(() -> rule.enforce("user", "12345678"));
    }

    @Test
    void T05_testEnforce_MaxLength_Boundary() {
        conf.setMaxLength(10);
        rule.setConf(conf);

        assertDoesNotThrow(() -> rule.enforce("user", "0123456789"));

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "01234567891"));
    }

    @Test
    void T06_testEnforce_RequireDigit_Boundary() {
        conf.setDigit(1);
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "password"));

        assertDoesNotThrow(() -> rule.enforce("user", "password1"));
    }

    @Test
    void T07_testEnforce_RequireUppercase_Boundary() {
        conf.setUppercase(1);
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "password"));

        assertDoesNotThrow(() -> rule.enforce("user", "Password"));
    }

    @Test
    void T08_testEnforce_WordsNotPermitted_ExactMatch() {
        conf.getWordsNotPermitted().add("secret");
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "secret"));
    }

    @Test
    void T09_testEnforce_WordsNotPermitted_CaseInsensitive() {
        conf.getWordsNotPermitted().add("secret");
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "SeCReT"));
    }

    @Test
    void T10_testEnforce_WordsNotPermitted_PartialMatch() {
        conf.getWordsNotPermitted().add("secret");
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("user", "topsecret123"));
    }

    @Test
    void T11_testEnforce_UsernameNotAllowed() {
        conf.setUsernameAllowed(false);
        rule.setConf(conf);

        assertThrows(RuntimeException.class, () -> rule.enforce("myuser", "myuser"));

        assertDoesNotThrow(() -> rule.enforce("myuser", "otherpass"));
    }

}
