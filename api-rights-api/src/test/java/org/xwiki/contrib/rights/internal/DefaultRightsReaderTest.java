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
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiBridge;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * @version $Id$
 */
@ComponentTest
@DefaultRightsTestComponentList
public class DefaultRightsReaderTest extends AbstractRightsTest
{
    @InjectMockComponents
    private DefaultRightsReader rightsReader;

    @MockComponent
    private XWikiBridge xwikiBridge;

    /**
     * Test that if we have a document with no parent, we get every rules of that document as actual rules (normalized)
     */
    @Test
    void getActualRules_Wiki()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rules when rules are asked for the wiki
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedWikiReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the parent document is empty, only the rules of the space are going to be taken into account for
     * the actual rights
     */
    @Test
    void getActualRules_Space_WikiNoRules()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return no rule at all for when rules are asked for the wiki
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Collections.emptyList());
        // ... and the following rules for the space
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the current document does not have any rules, the parent rules are going to be used
     */
    @Test
    void getActualRules_SpaceNoRules_Wiki()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return no rule at all for when rules are asked for the wiki
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the following rules for the space
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Collections.emptyList());
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent has a rule that has nothing in common with its child (subject / rights), every rule gets
     * added to the actual rights (and are normalized)
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectDifferentRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and a completely different rule for the space
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(2, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the exact same rules than its child, the rules are only added once
     */
    @Test
    void getActualRules_Space_WikiSameRule()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // ... and the exact same rule for the space
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the same subject than its child, but completely different rights, those
     * rights are added to the actual rights
     */
    @Test
    void getActualRules_Space_WikiSameSubjectDifferentRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different right
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        // The two rules should have merge to 1 with both VIEW and EDIT rights
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the same explicit rights than its child, but on different subjects, those
     * subjects are ignored from the actual rights (because overridden)
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectSameRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different subject
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has the same subject than its child, but has additional rights, those rights
     * are added too in the actual rights of the page
     */
    @Test
    void getActualRules_Space_WikiSameSubjectMoreRights()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with more rights
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW, Right.COMMENT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has part of the same rights than its child, but has additional rights and a
     * different subject, the subject does not get ignored for the extra rights it has
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectMoreRights()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW, Right.COMMENT),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different user and more rights
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(2, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.COMMENT),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has an additional subject and a different right, the subject appearing in both
     * rules will have both rights
     */
    @Test
    void getActualRules_Space_WikiMoreSubjectsDifferentRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different subject and more rights
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(2, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW, Right.EDIT),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiGuest"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has an additional subject and the same right, only the subject of the children
     * rule will have the right
     */
    @Test
    void getActualRules_Space_WikiMoreSubjectsSameRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different subject and more rights
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has different and several subjects and the same right, only the subject of the
     * children rule will have the right
     */
    @Test
    void getActualRules_Space_WikiDifferentSubjectsSameRight()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiGuest")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and the same rule for the space but with a different subject and more rights
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSpaceReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if the current document does not have any rules, nor its parent, parent of the parent rule are going to
     * be used
     */
    @Test
    void getActualRules_PageNoRule_SpaceNoRule_Wiki()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Collections.emptyList());
        // ... and a completely different rule for the space ...
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Collections.emptyList());
        // ... and a completely different rule for the document ...
        when(this.rightsReader.getRules(testedDocumentReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that the function is able to get actual rules up several parents
     */
    @Test
    void getActualRules_Page_SpaceDifferentRule_WikiDifferentRule()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and a completely different rule for the space ...
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.COMMENT),
                RuleState.ALLOW
            )));
        // ... and a completely different rule for the document ...
        when(this.rightsReader.getRules(testedDocumentReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        assertEquals(3, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.COMMENT),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.<Right>asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a parent document has no rule at all, it still goes up to the next parent
     */
    @Test
    void getActualRules_Page_SpaceNoRule_WikiDifferentRule()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and no rule for the space ...
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Collections.emptyList());
        // ... and a completely different rule for the document ...
        when(this.rightsReader.getRules(testedDocumentReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Bob")),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        assertEquals(2, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Bob"),
            false,
            Arrays.<Right>asList(Right.EDIT),
            RuleState.ALLOW
        );
    }

    /**
     * Test that if a there is no rules between two same rules in the document tree, this rule is only appearing once
     */
    @Test
    void getActualRules_Page_SpaceNoRule_WikiSameRule()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        SpaceReference testedSpaceReference = new SpaceReference("SP1", testedWikiReference);
        DocumentReference testedDocumentReference = new DocumentReference("DOC1", testedSpaceReference);
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and no rule for the space ...
        when(this.rightsReader.getRules(testedSpaceReference, false))
            .thenReturn(Collections.emptyList());
        // ... and a completely different rule for the document ...
        when(this.rightsReader.getRules(testedDocumentReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedDocumentReference);
        assertEquals(1, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
    }

    /**
     * Test that rights are being inherited from the main wiki if we are in a sub wiki
     */
    @Test
    void getActualRules_Subwiki_wiki()
    {
        WikiReference testedWikiReference = new WikiReference("xwiki");
        WikiReference testedSubWikiReference = new WikiReference("subwiki");
        // Mock reference to main wiki
        when(xwikiBridge.getMainWikiReference()).thenReturn(testedWikiReference);
        // return the following rule for when rules are asked for the wiki...
        when(this.rightsReader.getRules(testedWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                Collections.emptyList(),
                new RightSet(Right.VIEW),
                RuleState.ALLOW
            )));
        // ... and a completely different rule for the subwiki
        when(this.rightsReader.getRules(testedSubWikiReference, false))
            .thenReturn(Arrays.<ReadableSecurityRule>asList(new WritableSecurityRuleImpl(
                Collections.emptyList(),
                Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin")),
                new RightSet(Right.EDIT),
                RuleState.ALLOW
            )));
        // check what gets returned
        List<ReadableSecurityRule> inheritedRules = this.rightsReader.getActualRules(testedSubWikiReference);
        assertEquals(2, inheritedRules.size());
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
            true,
            Arrays.<Right>asList(Right.VIEW),
            RuleState.ALLOW
        );
        assertContainsRule(inheritedRules,
            new DocumentReference("xwiki", "XWiki", "Admin"),
            false,
            Arrays.<Right>asList(Right.EDIT),
            RuleState.ALLOW
        );
    }
}
