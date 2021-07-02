/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.rights.internal;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.model.internal.DefaultModelConfiguration;
import org.xwiki.model.internal.reference.DefaultEntityReferenceProvider;
import org.xwiki.model.internal.reference.DefaultStringEntityReferenceSerializer;
import org.xwiki.model.internal.reference.DefaultSymbolScheme;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.internal.model.reference.CurrentMixedEntityReferenceProvider;
import com.xpn.xwiki.internal.model.reference.CurrentMixedStringDocumentReferenceResolver;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @version $Id$
 */
@ComponentTest
@ComponentList({
    CurrentMixedStringDocumentReferenceResolver.class,
    DefaultStringEntityReferenceSerializer.class,
    DefaultSymbolScheme.class,
    DefaultEntityReferenceProvider.class,
    CurrentMixedEntityReferenceProvider.class,
    DefaultModelConfiguration.class,
})
public class DefaultSecurityRuleAbacusTest extends AbstractRightsTest
{
    @InjectMockComponents
    private DefaultSecurityRuleAbacus securityRuleAbacus;

    @MockComponent
    private RightsReader rightsReader;

    /**
     * Tests that a rule with 2 group subjects is split in 2 rules with a single group each and all the rest is copied
     * from the initial rule.
     */
    @Test
    void normalizeSubject_SplitMultipleGroups()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(new WritableSecurityRuleImpl(
            Arrays.asList(
                new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
            ),
            Collections.emptyList(),
            new RightSet(Right.VIEW),
            RuleState.ALLOW
        ));
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(2, actualNormalizedRules.size());
        // ... and actual rules after
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Tests that if there is a rule that sets a right to 2 subjects and then one of these subjects also has another
     * rule giving it some other rights, the normalization compacts this in 2 rules, one rule per group.
     */
    @Test
    void normalizeSubject_RegroupSubjects()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            // gives view to both admin group and all group
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
                ),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            ),
            // and then edit and comment only to admins
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT, Right.COMMENT),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(2, actualNormalizedRules.size());
        // ... and actual rules after
        // expect all group to only have view
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        // and admin group to have all 3 view, edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.EDIT, Right.COMMENT),
            RuleState.ALLOW
        );
    }

    /**
     * Tests that if rules have both groups and users, the normalization separates groups from users, while still
     * regrouping each subject to 1 single rule at the end
     */
    @Test
    void normalizeSubject_MixedGroupsAndUsers()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
                ),
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "Alice")
                ),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            ),
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")
                ),
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "Alice"),
                    new DocumentReference("xwiki", "XWiki", "Bob")
                ),
                new RightSet(Right.EDIT, Right.COMMENT),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(4, actualNormalizedRules.size());
        // ... and actual rules after
        // expect all group to only have view
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        // and admin group to have all 3 view, edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.EDIT, Right.COMMENT),
            RuleState.ALLOW
        );
        // and Alice to have all 3 view, edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "Alice"),
            false,
            Arrays.asList(Right.VIEW, Right.EDIT, Right.COMMENT),
            RuleState.ALLOW
        );
        // and Bob to have only edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.EDIT, Right.COMMENT),
            RuleState.ALLOW
        );
    }

    /**
     * Tests that if two rules are exactly the same, it is only kept once
     */
    @Test
    void normalizeSubject_SameRules()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            ),
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(1, actualNormalizedRules.size());
        // ... and actual rules after
        // expect admin group to only have view
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a rule has the same subject than another one, but has rights that are from it but also aren't from
     * it, we get a single rule with every rights.
     */
    @Test
    void normalizeSubject_SameRulesWithMoreRights()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW
            ),
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.EDIT),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(1, actualNormalizedRules.size());
        // ... and actual rules after
        // expect admin group to have all 3 view, edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.COMMENT, Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if there are more than one group on several rules, it works
     */
    @Test
    void normalizeSubject_n_times_n()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
                ),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW
            ),
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "CustomGroup")
                ),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.EDIT),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(3, actualNormalizedRules.size());
        // ... and actual rules after
        // expect admin group to have all 3 view, edit and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.COMMENT, Right.EDIT),
            RuleState.ALLOW
        );
        // expect all group to have view and comment
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.COMMENT),
            RuleState.ALLOW
        );
        // expect custom group to have view and edit
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "CustomGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if we try to normalize no rule, we actually get no rule
     */
    @Test
    void normalizeSubject_NoRules()
    {
        List<ReadableSecurityRule> rulesToNormalize = Collections.emptyList();
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(0, actualNormalizedRules.size());
    }

    /**
     * Test that if groups or users are null, it does not break
     */
    @Test
    void normalizeSubject_NullSubject()
    {
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(
            new WritableSecurityRuleImpl(
                null,
                null,
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW
            )
        );
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(0, actualNormalizedRules.size());
    }

    /**
     * Tests that if there are 2 rules for the same subject in a rule set, but they have different rule states (one is
     * allow and one is deny), the normalization doesn't regroup those. <br>
     * The normalize rules function is not really made to be used for these cases so we don't need to test all of them,
     * but in the worse case it should not normalize at all rather than break the rules.
     */
    @Test
    void normalizeSubject_DontRegroupRuleStates()
    {
        // give view to all group
        ReadableSecurityRule ruleAllow =
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            );
        // deny edit to all group
        ReadableSecurityRule ruleDeny =
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT),
                RuleState.DENY
            );
        List<ReadableSecurityRule> rulesToNormalize = Arrays.asList(ruleAllow, ruleDeny);
        // normalize the rules above
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRules(rulesToNormalize);
        // test the result. Count first...
        assertEquals(2, actualNormalizedRules.size());
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(actualNormalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }
}
