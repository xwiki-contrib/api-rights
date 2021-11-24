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
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.inject.Named;

import org.junit.jupiter.api.Test;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.DefaultSecurityReferenceFactory;
import org.xwiki.security.SecurityReference;
import org.xwiki.security.authorization.AuthorizationException;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.authorization.SecurityEntryReader;
import org.xwiki.security.authorization.SecurityRule;
import org.xwiki.security.internal.DefaultXWikiBridge;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * @version $Id$
 */
@ComponentTest
@ComponentList({
    DefaultXWikiBridge.class,
    DefaultSecurityReferenceFactory.class,
})
@ReferenceComponentList
@OldcoreTest
public class DefaultRightsReaderTest extends AbstractRightsTest
{
    @InjectMockComponents
    private DefaultRightsReader rightsReader;

    @InjectMockComponents
    private DefaultSecurityRuleAbacus securityRuleAbacus;

    @MockComponent
    @Named("api-rights")
    private SecurityEntryReader securityEntryReader;

    @InjectMockComponents
    private DefaultSecurityReferenceFactory securityReferenceFactory;

    /**
     * Test that if we have a document with no rules, we get an empty list of rules
     */
    @Test
    void getRules_NoRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Collections.emptyList());
        // check what gets returned for persisted rules
        List<ReadableSecurityRule> persistedRules = this.rightsReader.getRules(testedWikiReference, false);
        List<ReadableSecurityRule> normalizedPersistedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(persistedRules);
        assertEquals(0, normalizedPersistedRules.size());
        // check what gets returned for any rules
        List<ReadableSecurityRule> rules = this.rightsReader.getRules(testedWikiReference, true);
        List<ReadableSecurityRule> normalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rules);
        assertEquals(0, normalizedRules.size());
    }

    /**
     * Test that if we have a document with no parent, we get every rules of that document as actual rules (normalized)
     */
    @Test
    void getRules_OnlyImpliedRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                false
            )
        ));
        // check what gets returned for persisted rules
        List<ReadableSecurityRule> persistedRules = this.rightsReader.getRules(testedWikiReference, false);
        List<ReadableSecurityRule> normalizedPersistedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(persistedRules);
        assertEquals(0, normalizedPersistedRules.size());
        // check what gets returned for any rules
        List<ReadableSecurityRule> rules = this.rightsReader.getRules(testedWikiReference, true);
        List<ReadableSecurityRule> normalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rules);
        assertEquals(1, normalizedRules.size());
        assertContainsRule(normalizedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    @Test
    void getRules_OnlyImpliedDenyRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.DENY,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                false
            )
        ));
        // check what gets returned for persisted rules
        List<ReadableSecurityRule> persistedRules = this.rightsReader.getRules(testedWikiReference, false);
        List<ReadableSecurityRule> normalizedPersistedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(persistedRules);
        assertEquals(0, normalizedPersistedRules.size());
        // check what gets returned for any rules
        List<ReadableSecurityRule> rules = this.rightsReader.getRules(testedWikiReference, true);
        List<ReadableSecurityRule> normalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rules);
        assertEquals(1, normalizedRules.size());
        assertContainsRule(normalizedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.DENY
        );
    }

    /**
     * Test that if we have a document with no parent, we get every rules of that document as actual rules (normalized)
     */
    @Test
    void getRules_OnlyPersistedRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            )
        ));
        // check what gets returned for persisted rules
        List<ReadableSecurityRule> persistedRules = this.rightsReader.getRules(testedWikiReference, false);
        List<ReadableSecurityRule> normalizedPersistedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(persistedRules);
        assertEquals(1, normalizedPersistedRules.size());
        assertContainsRule(normalizedPersistedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        // check what gets returned for any rules
        List<ReadableSecurityRule> rules = this.rightsReader.getRules(testedWikiReference, true);
        List<ReadableSecurityRule> normalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rules);
        assertEquals(1, normalizedRules.size());
        assertContainsRule(normalizedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if we have a document with no parent, we get every rules of that document as actual rules (normalized)
     */
    @Test
    void getRules_MixOfImpliedAndPersistedRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ),
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                false
            )
        ));
        // check what gets returned for persisted rules
        List<ReadableSecurityRule> persistedRules = this.rightsReader.getRules(testedWikiReference, false);
        List<ReadableSecurityRule> normalizedPersistedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(persistedRules);
        assertEquals(1, normalizedPersistedRules.size());
        assertContainsRule(normalizedPersistedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        // check what gets returned for any rules
        List<ReadableSecurityRule> rules = this.rightsReader.getRules(testedWikiReference, true);
        List<ReadableSecurityRule> normalizedRules = this.securityRuleAbacus.normalizeRulesBySubject(rules);
        assertEquals(2, normalizedRules.size());
        assertContainsRule(normalizedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if we have a document with no parent, we get every rules of that document as actual rules (normalized)
     */
    @Test
    void getActualRules_Wiki() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // return the following rules when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            )
        ));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedWikiReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the parent document is empty, only the rules of the space are going to be taken into account for the
     * actual rights
     */
    @Test
    void getActualRules_Space_WikiNoRules() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return no rule at all for when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Collections.emptyList());
        // ... and the following rules for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the current document does not have any rules, the parent rules are going to be used
     */
    @Test
    void getActualRules_SpaceNoRules_Wiki() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return no rule at all for when rules are asked for the wiki
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // ... and the following rules for the space
        this.mockEntityReferenceRules(testedSpaceReference, Collections.emptyList());
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent has a rule that has nothing in common with its child (subject / rights), every rule gets
     * added to the actual rights (and are normalized)
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectDifferentRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a completely different rule for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent has a rule that has nothing in common with its child (subject / rights), every rule gets
     * added to the actual rights (and are normalized), with rules of different state.
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectDifferentRightDifferentState() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a completely different rule for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.DENY,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }

    /**
     * Test that if a parent document has the exact same rules than its child, the rules are only added once
     */
    @Test
    void getActualRules_Space_WikiSameRule() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the exact same rule for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the exact same rules than its child with different state, only the document
     * rule is kept.
     */
    @Test
    void getActualRules_Space_WikiSameRuleDifferentState() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the exact same rule for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.DENY,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }

    /**
     * Test that if a parent document has the same subject than its child, but completely different rights, those rights
     * are added to the actual rights
     */
    @Test
    void getActualRules_Space_WikiSameSubjectDifferentRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different right
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        // The two rules should have merge to 1 with both VIEW and EDIT rights
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the same subject than its child, but completely different rights and different
     * states, the rules are kept.
     */
    @Test
    void getActualRules_Space_WikiSameSubjectDifferentRightDifferentState() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different right
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.DENY,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }

    /**
     * Test that if a parent has a rule that has a right in common with its child for the same subject, the allow rule
     * is not returned anymore.
     */
    @Test
    void getActualRules_Space_WikiSameSubjectOverlappingRightDifferentState() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW, Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a completely different rule for the space
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.DENY,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }

    /**
     * Test that if a parent document has the same explicit rights than its child, but on different subjects, those
     * subjects are ignored from the actual rights (because overridden)
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectSameRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that a denying rule at a lower level for a different subject does not remove the allowing rule from a higher
     * level.
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectSameRightDifferentState() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return an allow rule at wiki level, for a right
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a deny rule at space level, for the same right but for a different subject
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.DENY,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
                true
            ))
        );
        // check what gets returned: both rules should be kept, even if they concern the same right, because they don't
        // actually overwrite eachother from a semantic pov.
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(2, inheritedRules.size());
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAllGroup"),
            true,
            Arrays.asList(Right.EDIT),
            RuleState.DENY
        );
    }

    /**
     * Test that if a parent document has the same subject than its child, but has additional rights, those rights are
     * added too in the actual rights of the page
     */
    @Test
    void getActualRules_Space_WikiSameSubjectMoreRights() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.COMMENT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has part of the same rights than its child, but has additional rights and a
     * different subject, the subject does not get ignored for the extra rights it has
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectMoreRights() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different user and more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.COMMENT),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has an additional subject and a different right, the subject appearing in both
     * rules will have both rights
     */
    @Test
    void getActualRules_Space_WikiMoreSubjectsDifferentRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject and more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiGuest"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has an additional subject and the same right, only the subject of the children
     * rule will have the right
     */
    @Test
    void getActualRules_Space_WikiMoreSubjectsSameRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject and more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has different and several subjects and the same right, only the subject of the
     * children rule will have the right
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectsSameRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject and more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has admin right on a subject, and the child page has an admin right on another
     * subject, both subject are going to appear with admin rights in the actual rules
     */
    @Test
    void getActualRules_SpaceAdminRight_WikiDifferentSubjectsAdminRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
    }

    /**
     * Test that the admin right is not deniable over several references
     */
    @Test
    void getActualRules_PageAdminRight_SpaceDifferentSubjectsAdminRight_WikiDifferentSubjectsAdminRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedParentSpaceReference = new SpaceReference("SP1", testedWikiReference);
        SpaceReference testedPageReference = new SpaceReference("SP2", testedParentSpaceReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject
        this.mockEntityReferenceRules(testedParentSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                Collections.emptyList(),
                true
            ))
        );
        // ... and the same rule for the page but with a different subject
        this.mockEntityReferenceRules(testedPageReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Alice")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedPageReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(3, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Alice"),
            false,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has an additional subject for a non-deniable right (admin), all subjects will have
     * the right after projection.
     */
    @Test
    void getActualRules_SpaceAdminRight_WikiMoreSubjectsAdminRight() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and the same rule for the space but with a different subject and more rights
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.ADMIN),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiGuest"),
            false,
            Arrays.asList(Right.ADMIN),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the current document does not have any rules, nor its parent, parent of the parent rule are going to
     * be used
     */
    @Test
    void getActualRules_PageNoRule_SpaceNoRule_Wiki() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // ... and a completely different rule for the space ...
        this.mockEntityReferenceRules(testedSpaceReference, Collections.emptyList());
        // ... and a completely different rule for the document ...
        this.mockEntityReferenceRules(testedDocumentReference, Collections.emptyList());

        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that the function is able to get actual rules up several parents
     */
    @Test
    void getActualRules_Page_SpaceDifferentRule_WikiDifferentRule() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a completely different rule for the space ...
        this.mockEntityReferenceRules(testedSpaceReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.COMMENT),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // ... and a completely different rule for the document ...
        this.mockEntityReferenceRules(testedDocumentReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(3, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.COMMENT),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has no rule at all, it still goes up to the next parent
     */
    @Test
    void getActualRules_Page_SpaceNoRule_WikiDifferentRule() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and no rule for the space ...
        this.mockEntityReferenceRules(testedSpaceReference, Collections.emptyList());
        // ... and a completely different rule for the document ...
        this.mockEntityReferenceRules(testedDocumentReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a there is no rules between two same rules in the document tree, this rule is only appearing once
     */
    @Test
    void getActualRules_Page_SpaceNoRule_WikiSameRule() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and no rule for the space ...
        this.mockEntityReferenceRules(testedSpaceReference, Collections.emptyList());
        // ... and a completely different rule for the document ...
        this.mockEntityReferenceRules(testedDocumentReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(1, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that rights are being inherited from the main wiki if we are in a sub wiki
     */
    @Test
    void getActualRules_Subwiki_wiki() throws Exception
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        WikiReference testedSubWikiReference = new WikiReference("subwiki");
        // return the following rule for when rules are asked for the wiki...
        this.mockEntityReferenceRules(testedWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.VIEW),
                RuleState.ALLOW,
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                true
            ))
        );
        // ... and a completely different rule for the subwiki
        this.mockEntityReferenceRules(testedSubWikiReference, Arrays.asList(
            new XWikiSecurityRule(
                new RightSet(Right.EDIT),
                RuleState.ALLOW,
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                Collections.emptyList(),
                true
            ))
        );
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSubWikiReference);
        List<ReadableSecurityRule> normalizedInheritedRules =
            this.securityRuleAbacus.normalizeRulesBySubject(inheritedRules);
        assertEquals(2, normalizedInheritedRules.size());
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(normalizedInheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    private void mockEntityReferenceRules(EntityReference entityReference, Collection<ReadableSecurityRule> rules)
    {
        SecurityReference securityReference = this.securityReferenceFactory.newEntityReference(entityReference);
        try {
            when(this.securityEntryReader.read(eq(securityReference)))
                .thenReturn(new DefaultSecurityRuleEntry(
                    securityReference,
                    new ArrayList<SecurityRule>(rules)
                ));
        } catch (AuthorizationException e) {
            fail("Error: securityEntryReader.read should not have failed");
        }
    }
}
