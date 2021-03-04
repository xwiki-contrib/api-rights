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
package org.xwiki.contrib.rights.internal.bridge;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.contrib.rights.internal.DefaultRightsWriter;
import org.xwiki.contrib.rights.internal.WritableSecurityRuleImpl;
import org.xwiki.job.event.status.JobProgressManager;
import org.xwiki.localization.ContextualLocalizationManager;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.model.reference.SpaceReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RightSet;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;
import org.xwiki.sheet.SheetBinder;
import org.xwiki.test.annotation.ComponentList;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.internal.mandatory.XWikiGlobalRightsDocumentInitializer;
import com.xpn.xwiki.internal.mandatory.XWikiRightsDocumentInitializer;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.GroupsClass;
import com.xpn.xwiki.objects.classes.LevelsClass;
import com.xpn.xwiki.objects.classes.UsersClass;
import com.xpn.xwiki.test.MockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.InjectMockitoOldcore;
import com.xpn.xwiki.test.junit5.mockito.OldcoreTest;
import com.xpn.xwiki.test.reference.ReferenceComponentList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({ XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class })
class DefaultRightsWriterTest
{
    private static final String XWIKI_SPACE = "XWiki";

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    private static final String XWIKI_RIGHTS_CLASS_DOC_NAME = "XWiki.XWikiRights";

    private static final String XWIKI_GLOBAL_RIGHTS_CLASS_DOC_NAME = "XWiki.XWikiGlobalRights";

    private static final String GROUPS_PROPERTY = "groups";

    private static final EntityReference XWIKI_RIGHTS_CLASS =
        new EntityReference("XWikiRights", EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    private static final EntityReference XWIKI_GLOBAL_RIGHTS_CLASS = new EntityReference("XWikiGlobalRights",
        EntityType.DOCUMENT, new EntityReference(XWIKI_SPACE, EntityType.SPACE));

    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private ObservationManager obsManager;

    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private JobProgressManager jobsProgressManager;

    /* Mocked for the mockito old core to not fail when trying to initialize the documents */
    @MockComponent
    private ContextualLocalizationManager localizationManager;

    /*
     * Mocked for the initializers, they use the sheet binder to check if some specific sheet needs to be bound to the
     * classes, we don't care so we put an empty mock.
     */
    @MockComponent
    @Named("document")
    private SheetBinder documentSheetBinder;

    @InjectMockitoOldcore
    private MockitoOldcore oldcore;

    @InjectMockComponents
    private DefaultRightsWriter rightsWriter;

    @BeforeEach
    void setUp()
    {
        this.oldcore.getSpyXWiki().initializeMandatoryDocuments(this.oldcore.getXWikiContext());
    }

    @Test
    void saveRulesOnObject() throws XWikiException
    {
        EntityReference objRef = new ObjectReference("XWiki.XWikiComments", new DocumentReference("xwiki", "S", "P"));

        Exception exc = assertThrows(UnsupportedOperationException.class, () -> {
            // Content throwing exception here
            this.rightsWriter.saveRules(Collections.emptyList(), objRef);
        });

        assertEquals("Could not set rights for the given reference.", exc.getMessage());
    }

    @Test
    void saveViewRuleOnDocument() throws Exception
    {
        // prepare a document to put rights on
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document
        WritableSecurityRule rule = new WritableSecurityRuleImpl();
        rule.setGroups(Collections.emptyList());
        rule.setUsers(Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdmin")));
        rule.setState(RuleState.ALLOW);
        rule.setRights(Arrays.asList(Right.VIEW));

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        Document resultDocEasyAPI = new Document(resultDoc, this.oldcore.getXWikiContext());
        // check that there is an object set
        assertEquals(1, resultDocEasyAPI.getxWikiObjects().size());
        // check that the object is of the good class and has number 0
        assertEquals(1, resultDocEasyAPI.getObjects("XWiki.XWikiRights").size());
        assertEquals(0, resultDocEasyAPI.getObject("XWiki.XWikiRights").getNumber());
    }

    @Test
    void replaceExistingRuleOnPage() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        WritableSecurityRule rule = new WritableSecurityRuleImpl();
        rule.setState(RuleState.DENY);

        this.rightsWriter.saveRules(Collections.singletonList(rule), documentReference);

        XWikiDocument modifiedDocument = this.oldcore.getSpyXWiki().getDocument(documentReference,
            this.oldcore.getXWikiContext());

        assertEquals(1, modifiedDocument.getXObjects(XWIKI_RIGHTS_CLASS).size());
        assertEquals(0, modifiedDocument.getXObject(XWIKI_RIGHTS_CLASS).getNumber());
        assertEquals(0,
            modifiedDocument.getXObjects(XWIKI_RIGHTS_CLASS).get(0).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        // Add a new rule, so the old one will be deleted.
        rule.setState(RuleState.ALLOW);
        this.rightsWriter.saveRules(Collections.singletonList(rule), documentReference);
        // Can't directly check the size of getXObjects(), since the first object is not entirely deleted.
        assertNull(modifiedDocument.getXObjects(XWIKI_RIGHTS_CLASS).get(0));
        assertNotNull(modifiedDocument.getXObjects(XWIKI_RIGHTS_CLASS).get(1));
        assertEquals(1,
            modifiedDocument.getXObjects(XWIKI_RIGHTS_CLASS).get(1).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
        assertEquals(1, modifiedDocument.getXObject(XWIKI_RIGHTS_CLASS).getNumber());
    }

    @Test
    void saveEditRuleOnSpace() throws XWikiException
    {
        SpaceReference spaceReference = new SpaceReference("XWiki", new WikiReference("xwiki"));
        WritableSecurityRule writableSecurityRule = new WritableSecurityRuleImpl();
        writableSecurityRule.setRights(new RightSet(Right.COMMENT));
        writableSecurityRule
            .setGroups(Arrays.asList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup"),
                new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")));
        writableSecurityRule.setUsers(Arrays.asList(new DocumentReference("xwiki", "XWiki", "Admin"),
            new DocumentReference("xwiki", "XWiki", "SimpleUser")));

        this.rightsWriter.saveRules(Collections.singletonList(writableSecurityRule), spaceReference);

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(new DocumentReference("xwiki",
            XWIKI_SPACE, XWIKI_WEB_PREFERENCES), oldcore.getXWikiContext());
        List<BaseObject> objects = document.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertEquals(1, objects.size());

        assertEquals(Arrays.asList("XWiki.Admin", "XWiki.SimpleUser"),
            UsersClass.getListFromString(objects.get(0).getLargeStringValue("users")));
        assertEquals(Arrays.asList("XWiki.XWikiAdminGroup", "XWiki.XWikiAllGroup"),
            GroupsClass.getListFromString(objects.get(0).getLargeStringValue("groups")));
        assertEquals("comment", objects.get(0).getLargeStringValue("levels"));
        assertEquals(1, objects.get(0).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }

    /**
     * Adds an edit rule on the main wiki.
     */
    @Test
    void saveEditRuleOnMainWiki() throws XWikiException
    {
        WikiReference wikiReference = new WikiReference("xwiki");
        WritableSecurityRule writableSecurityRule = new WritableSecurityRuleImpl();
        writableSecurityRule.setGroups(Collections.singletonList(new DocumentReference("xwiki", "XWiki",
            "XWikiAllGroup")));
        writableSecurityRule.setRights(new RightSet(Right.EDIT));
        rightsWriter.saveRules(Collections.singletonList(writableSecurityRule), wikiReference);
        EntityReference xwikiPreferences = new DocumentReference("xwiki", XWIKI_SPACE, "XWikiPreferences");
        XWikiDocument document =
            oldcore.getSpyXWiki().getDocument(xwikiPreferences, oldcore.getXWikiContext());
        assertEquals(1, document.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        // TODO: assert that the properties are persisted.
    }

    @Test
    void addMultipleRulesOnPage() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "TestPage");
        WritableSecurityRule rule1 = new WritableSecurityRuleImpl();
        WritableSecurityRule rule2 = new WritableSecurityRuleImpl();
        WritableSecurityRule rule3 = new WritableSecurityRuleImpl();
        rule1.setRights(Arrays.asList(Right.PROGRAM, Right.EDIT));
        rule1.setState(RuleState.DENY);

        rule2.setRights(Collections.singletonList(Right.VIEW));
        rule2.setState(RuleState.ALLOW);

        rule3.setState(RuleState.ALLOW);
        rule3.setUsers(Collections.singletonList(new DocumentReference("xwiki", XWIKI_SPACE, "XWikiAdmin")));

        rightsWriter.saveRules(Arrays.asList(rule1, rule2, rule3), documentReference);

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        assertEquals(3, document.getXObjects(XWIKI_RIGHTS_CLASS).size());

        assertEquals(Arrays.asList(Right.EDIT.getName(), Right.PROGRAM.getName()),
            LevelsClass
                .getListFromString(document.getXObjects(XWIKI_RIGHTS_CLASS).get(0).getLargeStringValue("levels")));
        assertEquals(0, document.getXObjects(XWIKI_RIGHTS_CLASS).get(0).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        assertEquals(Collections.singletonList(Right.VIEW.getName()),
            LevelsClass
                .getListFromString(document.getXObjects(XWIKI_RIGHTS_CLASS).get(1).getLargeStringValue("levels")));
        assertEquals(1, document.getXObjects(XWIKI_RIGHTS_CLASS).get(1).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            UsersClass
                .getListFromString(document.getXObjects(XWIKI_RIGHTS_CLASS).get(2).getLargeStringValue("users")));
        assertEquals(1, document.getXObjects(XWIKI_RIGHTS_CLASS).get(2).getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }

    @Test
    void testThatNeedsToBeRenamed() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "Space", "Page");
        XWikiDocument xWikiDocument =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());

        Document document = new Document(xWikiDocument, this.oldcore.getXWikiContext());
        assertEquals(0, document.getObjects(XWIKI_RIGHTS_CLASS_DOC_NAME).size());
        assertEquals(0, document.getObjects(XWIKI_GLOBAL_RIGHTS_CLASS_DOC_NAME).size());

        WritableSecurityRule rule = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        this.rightsWriter.saveRules(Collections.singletonList(rule), documentReference);

        XWikiDocument resultDoc =
            oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightObject = resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).get(0);
        assertEquals(0, rightObject.getNumber());

        WritableSecurityRule ruleToBeCopied = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.emptyList(), new RightSet(Right.PROGRAM), RuleState.ALLOW);
        this.rightsWriter.copyRuleIntoBaseObject(rightObject, ruleToBeCopied);

        assertEquals(0, rightObject.getNumber());
    }

    @Test
    void replaceWithLessRules() throws XWikiException
    {
        SpaceReference spaceReference = new SpaceReference("xwiki", "Space", "Page");
        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumb1 = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Arrays.asList(dumb, dumb1, dumb, dumb1), spaceReference);

        DocumentReference spaceWebPreferencesRef = new DocumentReference(XWIKI_WEB_PREFERENCES, spaceReference);
        XWikiDocument spaceWebPreferencesDoc =
            oldcore.getSpyXWiki().getDocument(spaceWebPreferencesRef, oldcore.getXWikiContext());

        int expected = 4;
        assertEquals(expected, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        for (int i = 0; i < expected; ++i) {
            assertEquals(i, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(i).getNumber());
        }

        WritableSecurityRule ruleToCopy = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.PROGRAM, Right.VIEW), RuleState.ALLOW);

        this.rightsWriter
            .addRightsByRecyclingObjects(Collections.singletonList(ruleToCopy), spaceWebPreferencesDoc,
                XWIKI_GLOBAL_RIGHTS_CLASS);

        assertEquals(1, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        assertEquals(0, spaceWebPreferencesDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getNumber());
    }

    @Test
    void replaceWithMoreRules() throws XWikiException
    {
        // copy a rule in the same object & test if it copied all the fields
        DocumentReference documentReference = new DocumentReference("xwiki", "SandBox", "Main");

        DocumentReference user1 = new DocumentReference("xwiki", "XWiki", "Admin");
        DocumentReference user2 = new DocumentReference("xwiki", "test1", "p");
        DocumentReference user3 = new DocumentReference("xwiki", "userSpace", "user");

        DocumentReference group1 = new DocumentReference("xwiki", "XWiki", "group");
        DocumentReference group2 = new DocumentReference("xwiki", "space", "group1");
        DocumentReference group3 = new DocumentReference("xwiki", "MySpace", "group3");
        DocumentReference group4 = new DocumentReference("xwiki", "Something", "group4");

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Arrays.asList(group1, group2), Arrays.asList(user1,
            user2), new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumbRight2 = new WritableSecurityRuleImpl(Arrays.asList(group3, group4),
            Collections.singletonList(user3), new RightSet(Right.VIEW, Right.PROGRAM, Right.EDIT), RuleState.DENY);

        rightsWriter.saveRules(Arrays.asList(dumb, dumbRight2), documentReference);

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        int noPersistedObjects = 2;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());

        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }

        rightsWriter.addRightsByRecyclingObjects(Arrays.asList(dumbRight2, dumb, dumbRight2, dumbRight2),
            document, XWIKI_RIGHTS_CLASS);

        noPersistedObjects = 4;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());
        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }
    }

    @Test
    void copyRuleIntoBaseObjectForGlobalRights() throws XWikiException
    {
        copyRuleIntoBaseObjects(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS);
    }

    @Test
    void copyRuleIntoBaseObjectForNormalRights() throws XWikiException
    {
        copyRuleIntoBaseObjects(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS);
    }

    private void copyRuleIntoBaseObjects(EntityReference whereToSaveRules, EntityReference rightsClassReference)
        throws XWikiException
    {
        // copy a rule in the same object & test if it copied all the fields
        WritableSecurityRule dumbRule = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT, Right.VIEW), RuleState.DENY);

        rightsWriter.saveRules(Collections.singletonList(dumbRule), whereToSaveRules);

        XWikiDocument document = null;
        if (EntityType.SPACE == whereToSaveRules.getType()) {
            DocumentReference spaceWebPreferencesRef = new DocumentReference(XWIKI_WEB_PREFERENCES,
                (SpaceReference) whereToSaveRules);
            document =
                oldcore.getSpyXWiki().getDocument(spaceWebPreferencesRef, oldcore.getXWikiContext());
        } else if (EntityType.DOCUMENT == whereToSaveRules.getType()) {
            document = oldcore.getSpyXWiki().getDocument(whereToSaveRules, oldcore.getXWikiContext());
        }
        assertNotNull(document);
        List<BaseObject> objects = document.getXObjects(rightsClassReference);
        BaseObject right = objects.get(0);

        // before
        assertEquals(Collections.emptyList(), UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.emptyList(), GroupsClass.getListFromString(right.getLargeStringValue("groups")));

        assertEquals(Arrays.asList("view", "edit", "comment"), LevelsClass.getListFromString(right.getLargeStringValue(
            "levels")));
        assertEquals(0, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");
        WritableSecurityRule dumbRule2 = new WritableSecurityRuleImpl(Collections.singletonList(adminUserDocRef),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.copyRuleIntoBaseObject(right, dumbRule2);

        objects = document.getXObjects(rightsClassReference);
        right = objects.get(0);
        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            GroupsClass.getListFromString(right.getLargeStringValue("groups")));

        assertEquals(Collections.singletonList("view"), LevelsClass.getListFromString(right.getLargeStringValue(
            "levels")));
        assertEquals(1, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }

    /**
     * Helper function to setup manatory classes on a different subwiki than the main wiki.
     *
     * @param wikiname the wiki name to initialize mandatory classes on
     */
    private void initializeMandatoryDocsOnWiki(String wikiname)
    {
        String oldWikiId = this.oldcore.getXWikiContext().getWikiId();
        try {
            this.oldcore.getXWikiContext().setWikiId(wikiname);
            this.oldcore.getSpyXWiki().initializeMandatoryDocuments(this.oldcore.getXWikiContext());
        } catch (Exception e) {
            // Dunno what else to do, but definitely I should do something smarter
            e.printStackTrace();
        } finally {
            this.oldcore.getXWikiContext().setWikiId(oldWikiId);
        }
    }

    @Test
    void testAddRightsGroupOnTheSameWiki() throws XWikiException
    {
        // initialize mandatory classes on the subwiki to test things on
        initializeMandatoryDocsOnWiki("subwiki");

        DocumentReference documentReference = new DocumentReference("subwiki", "S", "P");
        // prepare rules to put on the document
        WritableSecurityRule rule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("subwiki", "XWiki", "XWikiAdminGroup")),
            Collections.emptyList(), new RightSet(Right.VIEW), RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        // check that the value of the group set in the object is not prefixed
        assertEquals("XWiki.XWikiAdminGroup",
            resultDoc.getXObject(XWIKI_RIGHTS_CLASS).getLargeStringValue(GROUPS_PROPERTY));
    }

    @Test
    void testAddRightsGroupOnDifferentWiki() throws XWikiException
    {
        // initialize mandatory classes on the subwiki to test things on
        initializeMandatoryDocsOnWiki("subwiki");

        DocumentReference documentReference = new DocumentReference("subwiki", "S", "P");
        // prepare rules to put on the document
        WritableSecurityRule rule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
            Collections.emptyList(), new RightSet(Right.VIEW), RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        Document resultDocEasyAPI = new Document(resultDoc, this.oldcore.getXWikiContext());
        // check that there is an object set
        assertEquals(1, resultDocEasyAPI.getxWikiObjects().size());
        // check that the value of the group set in the object is prefixed
        assertEquals("xwiki:XWiki.XWikiAdminGroup",
            resultDocEasyAPI.getObject("XWiki.XWikiRights").getValue(GROUPS_PROPERTY));
    }
}
