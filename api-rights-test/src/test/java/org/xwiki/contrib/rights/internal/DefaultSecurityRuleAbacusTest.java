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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.SecurityRuleDiff;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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
        List<ReadableSecurityRule> actualNormalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rulesToNormalize);
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

    @Test
    void computeDiff_changeRight()
    {
        List<ReadableSecurityRule> previousRules = Arrays.asList(
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

        List<ReadableSecurityRule> currentRules = Arrays.asList(
            // gives view to both admin group and all group
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
                ),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.EDIT),
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

        List<SecurityRuleDiff> securityRuleDiffs = this.securityRuleAbacus.computeRuleDiff(previousRules, currentRules);
        assertEquals(1, securityRuleDiffs.size());

        DefaultSecurityRuleDiff expectedDiff = new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_UPDATED,
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW),
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.EDIT),
                RuleState.ALLOW),
            Collections.singleton(SecurityRuleDiff.PropertyType.RIGHTS)
            );
        assertEquals(expectedDiff, securityRuleDiffs.get(0));
    }

    @Test
    void computeDiff_changeState()
    {
        List<ReadableSecurityRule> previousRules = Arrays.asList(
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

        List<ReadableSecurityRule> currentRules = Arrays.asList(
            // gives view to both admin group and all group
            new WritableSecurityRuleImpl(
                Arrays.asList(
                    new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                    new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")
                ),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.DENY
            ),
            // and then edit and comment only to admins
            new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT, Right.COMMENT),
                RuleState.ALLOW
            )
        );

        List<SecurityRuleDiff> securityRuleDiffs = this.securityRuleAbacus.computeRuleDiff(previousRules, currentRules);
        assertEquals(4, securityRuleDiffs.size());

        DefaultSecurityRuleDiff expectedDiff1 = new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_UPDATED,
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.EDIT, Right.COMMENT),
                RuleState.ALLOW),
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT, Right.COMMENT),
                RuleState.ALLOW),
            Collections.singleton(SecurityRuleDiff.PropertyType.RIGHTS)
        );
        assertEquals(expectedDiff1, securityRuleDiffs.get(0));

        DefaultSecurityRuleDiff expectedDiff2 = new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_DELETED,
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW),
            null,
            Collections.emptySet()
        );
        assertEquals(expectedDiff2, securityRuleDiffs.get(1));

        DefaultSecurityRuleDiff expectedDiff3 = new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_ADDED,
            null,
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.DENY),
            Collections.emptySet()
        );
        assertEquals(expectedDiff3, securityRuleDiffs.get(2));

        DefaultSecurityRuleDiff expectedDiff4 = new DefaultSecurityRuleDiff(SecurityRuleDiff.ChangeType.RULE_ADDED,
            null,
            new WritableSecurityRuleImpl(
                Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.DENY),
            Collections.emptySet()
        );
        assertEquals(expectedDiff4, securityRuleDiffs.get(3));
    }

    /**
     * Tests that only the rules whose subject is a user are extracted from a set of rules containing both user and
     * group subjects and test that the resulted rules are normalized
     */
    @Test
    void getUserRulesNormalized()
    {
        DocumentReference group1DocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup");
        DocumentReference group2DocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiAllGroup");
        DocumentReference user1DocumentReference = new DocumentReference("xwiki", "XWiki", "JohnDoe");
        DocumentReference user2DocumentReference = new DocumentReference("xwiki", "XWiki", "JaneDoe");

        List<ReadableSecurityRule> rules = Arrays.asList(
            new WritableSecurityRuleImpl(Arrays.asList(group1DocumentReference, group2DocumentReference),
                Arrays.asList(user1DocumentReference), new RightSet(Right.VIEW, Right.COMMENT), RuleState.ALLOW),
            new WritableSecurityRuleImpl(Collections.emptyList(), Arrays.asList(user2DocumentReference),
                new RightSet(Right.EDIT), RuleState.ALLOW),
            new WritableSecurityRuleImpl(Collections.emptyList(), Arrays.asList(user1DocumentReference),
                new RightSet(Right.EDIT), RuleState.ALLOW));

        List<ReadableSecurityRule> userRulesNormalized = this.securityRuleAbacus.getUserRulesNormalized(rules);

        // Test the number of results
        assertEquals(2, userRulesNormalized.size());

        // Expect to have 1 rule for JohDoe with view, comment, and edit rights allowed and one rule for JaneDoe with
        // edit right allowed.
        assertContainsRule(userRulesNormalized, new DocumentReference("xwiki", "XWiki", "JohnDoe"), false,
            Arrays.asList(Right.VIEW, Right.COMMENT, Right.EDIT), RuleState.ALLOW);
        assertContainsRule(userRulesNormalized, new DocumentReference("xwiki", "XWiki", "JaneDoe"), false,
            Arrays.asList(Right.EDIT), RuleState.ALLOW);
    }

    /**
     * Tests that only the rules whose subject is a group are extracted from a set of rules containing both user and
     * group subjects and test that the resulted rules are normalized
     */
    @Test
    void getGroupRulesNormalized()
    {
        DocumentReference group1DocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup");
        DocumentReference group2DocumentReference = new DocumentReference("xwiki", "XWiki", "CustomGroup");
        DocumentReference group3DocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiAllGroup");
        DocumentReference user1DocumentReference = new DocumentReference("xwiki", "XWiki", "JohnDoe");
        DocumentReference user2DocumentReference = new DocumentReference("xwiki", "XWiki", "JaneDoe");

        List<ReadableSecurityRule> rules = Arrays.asList(
            new WritableSecurityRuleImpl(Arrays.asList(group1DocumentReference, group2DocumentReference),
                Arrays.asList(user1DocumentReference), new RightSet(Right.VIEW, Right.EDIT), RuleState.ALLOW),
            new WritableSecurityRuleImpl(Arrays.asList(group3DocumentReference), Arrays.asList(user2DocumentReference),
                new RightSet(Right.VIEW), RuleState.DENY));

        List<ReadableSecurityRule> groupRulesNormalized = this.securityRuleAbacus.getGroupRulesNormalized(rules);

        // Test the number of results
        assertEquals(3, groupRulesNormalized.size());

        // Expect to have one rule for XWikiAdminGroup with view and edit rights allowed, one rule for CustomGroup with
        // view and edit rights allowed, and one rule for XWikiAllGroup with view right denied.
        assertContainsRule(groupRulesNormalized, group1DocumentReference, true, Arrays.asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW);
        assertContainsRule(groupRulesNormalized, group2DocumentReference, true, Arrays.asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW);
        assertContainsRule(groupRulesNormalized, group3DocumentReference, true, Arrays.asList(Right.VIEW),
            RuleState.DENY);
    }

    /**
     * Tests that rules are organized by subject and state
     */
    @Test
    void organizeRulesBySubjectAndState()
    {
        DocumentReference groupDocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiAllGroup");
        DocumentReference userDocumentReference = new DocumentReference("xwiki", "XWiki", "JohnDoe");

        List<ReadableSecurityRule> rules = Arrays.asList(
            new WritableSecurityRuleImpl(Arrays.asList(groupDocumentReference), Arrays.asList(userDocumentReference),
                new RightSet(Right.VIEW, Right.COMMENT), RuleState.ALLOW),
            new WritableSecurityRuleImpl(Arrays.asList(groupDocumentReference), Arrays.asList(userDocumentReference),
                new RightSet(Right.EDIT), RuleState.ALLOW),
            new WritableSecurityRuleImpl(Collections.emptyList(), Arrays.asList(userDocumentReference),
                new RightSet(Right.DELETE), RuleState.DENY));

        Map<DocumentReference, Pair<ReadableSecurityRule, ReadableSecurityRule>> organizedRules =
            this.securityRuleAbacus.organizeRulesBySubjectAndState(rules);

        // Expect to have a Map of results with 2 entries
        assertEquals(2, organizedRules.size());

        // Expect one entry with key=JohnDoe DocumentReference and value=Pair{(rule with view,comment, edit rights
        // allowed), (rule with delete right denied)}
        assertTrue(organizedRules.containsKey(userDocumentReference));
        assertNotNull(organizedRules.get(userDocumentReference));
        assertNotNull(organizedRules.get(userDocumentReference).getLeft());
        assertContainsRule(Arrays.asList(organizedRules.get(userDocumentReference).getLeft()), userDocumentReference,
            false, Arrays.asList(Right.VIEW, Right.COMMENT, Right.EDIT), RuleState.ALLOW);
        assertNotNull(organizedRules.get(userDocumentReference).getRight());
        assertContainsRule(Arrays.asList(organizedRules.get(userDocumentReference).getRight()), userDocumentReference,
            false, Arrays.asList(Right.DELETE), RuleState.DENY);

        // Expect one entry with key=XWikiAllGroup DocumentReference and value=Pair{(rule with view,comment, edit rights
        // allowed), null}
        assertTrue(organizedRules.containsKey(groupDocumentReference));
        assertNotNull(organizedRules.get(groupDocumentReference));
        assertNotNull(organizedRules.get(groupDocumentReference).getLeft());
        assertContainsRule(Arrays.asList(organizedRules.get(groupDocumentReference).getLeft()), groupDocumentReference,
            true, Arrays.asList(Right.VIEW, Right.COMMENT, Right.EDIT), RuleState.ALLOW);
        assertNull(organizedRules.get(groupDocumentReference).getRight());
    }

    /**
     * XWiki Guest user subject is stored as null value in rule objects, so, the objective of this test is to make sure
     * that the correct Guest user DocumentReference (XWiki.XWikiGuest) is returned by the
     * organizeRulesBySubjectAndState() method
     */
    @Test
    void organizeRulesBySubjectAndState_GuestUser()
    {
        DocumentReference guestDocumentReference = new DocumentReference("xwiki", "XWiki", "XWikiGuest");
        ArrayList<DocumentReference> userList = new ArrayList<DocumentReference>();
        userList.add(null);
        List<ReadableSecurityRule> rules = Arrays.asList(
            new WritableSecurityRuleImpl(Collections.emptyList(), userList, new RightSet(Right.VIEW), RuleState.ALLOW));

        Map<DocumentReference, Pair<ReadableSecurityRule, ReadableSecurityRule>> organizedRules =
            this.securityRuleAbacus.organizeRulesBySubjectAndState(rules);

        // Expect to have a Map of results with 1 entry with Key=XWiki.XWikiGuest and value=Pair{(rule with view right
        // allowed), null}
        assertEquals(1, organizedRules.size());
        assertNotNull(organizedRules.get(guestDocumentReference));
        assertNotNull(organizedRules.get(guestDocumentReference).getLeft());
        assertContainsRule(Arrays.asList(organizedRules.get(guestDocumentReference).getLeft()), null, false,
            Arrays.asList(Right.VIEW), RuleState.ALLOW);
        assertNull(organizedRules.get(guestDocumentReference).getRight());
    }
}
