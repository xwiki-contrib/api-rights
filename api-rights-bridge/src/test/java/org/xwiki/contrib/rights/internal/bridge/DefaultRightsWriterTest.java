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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.contrib.rights.internal.DefaultRightsWriter;
import org.xwiki.contrib.rights.internal.IncrementingObjectNumbersRulesWriter;
import org.xwiki.contrib.rights.internal.RecyclingObjectsRulesWriter;
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
@ComponentList({XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class,
    IncrementingObjectNumbersRulesWriter.class, RecyclingObjectsRulesWriter.class})
class DefaultRightsWriterTest
{
    private static final String XWIKI_SPACE = "XWiki";

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

    private static final String XWIKI_RIGHTS_CLASS_DOC_NAME = "XWiki.XWikiRights";

    private static final String XWIKI_GLOBAL_RIGHTS_CLASS_DOC_NAME = "XWiki.XWikiGlobalRights";

    private static final String GROUPS_PROPERTY = "groups";

    private static final String USERS_PROPERTY = "users";

    private static final String LEVELS_PROPERTY = "levels";

    private static final String ALLOW_PROPERTY = "allow";

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

        // check that the desired right was added...
        // ... a single one 
        assertEquals(1, getNonNullObjects(XWIKI_RIGHTS_CLASS, modifiedDocument).size());
        BaseObject testedObject = modifiedDocument.getXObject(XWIKI_RIGHTS_CLASS);
        // ... with values from the rule
        assertEquals("", testedObject.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("", testedObject.getLargeStringValue(USERS_PROPERTY));
        assertEquals("", testedObject.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(0, testedObject.getIntValue(ALLOW_PROPERTY));
        
        // Add a new rule, so the old one will be deleted.
        rule.setState(RuleState.ALLOW);
        rule.setGroups(Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")));
        this.rightsWriter.saveRules(Collections.singletonList(rule), documentReference);
        
        // Check that indeed previous object was replaced with a new one.
        modifiedDocument = this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // there is a single object
        assertEquals(1, getNonNullObjects(XWIKI_RIGHTS_CLASS, modifiedDocument).size());
        // the object has changed to the implement new rule
        testedObject = modifiedDocument.getXObject(XWIKI_RIGHTS_CLASS);
        assertEquals("XWiki.XWikiAllGroup", testedObject.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("", testedObject.getLargeStringValue(USERS_PROPERTY));
        assertEquals("", testedObject.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(1, testedObject.getIntValue(ALLOW_PROPERTY));
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
    void testSaveRuleWithNullUsers() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with null users list
        WritableSecurityRule rule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")), null,
            new RightSet(Right.VIEW), RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the users are set to empty
        assertEquals("", rightsObj.getLargeStringValue(USERS_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("XWiki.XWikiAdminGroup", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("view", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
    }

    @Test
    void testSaveRuleWithNullGroups() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with null groups
        WritableSecurityRule rule = new WritableSecurityRuleImpl(null,
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the groups are set to empty
        assertEquals("", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("XWiki.Admin", rightsObj.getLargeStringValue(USERS_PROPERTY));
        assertEquals("view", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
    }

    @Test
    void testSaveRuleWithNullUsersAndGroups() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with null for both users and groups
        WritableSecurityRule rule = new WritableSecurityRuleImpl(null, null, new RightSet(Right.VIEW), RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the users and groups are set to empty
        assertEquals("", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("", rightsObj.getLargeStringValue(USERS_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("view", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
    }

    @Test
    void testSaveRuleWithNullRights() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with null rights set
        WritableSecurityRule rule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
            Collections.emptyList(), null, RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the rights are set to none
        assertEquals("", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("", rightsObj.getLargeStringValue(USERS_PROPERTY));
        assertEquals("XWiki.XWikiAdminGroup", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
    }

    @Test
    void testSaveRuleWithNullAllowDefaultsToTrue() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with null rule state
        WritableSecurityRule rule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
            Collections.emptyList(), new RightSet(Right.VIEW), null);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the allow is set to default true
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("", rightsObj.getLargeStringValue(USERS_PROPERTY));
        assertEquals("XWiki.XWikiAdminGroup", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("view", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
    }

    @Test
    void testSaveRuleWithEmptyUsersAndGroups() throws XWikiException
    {
        DocumentReference documentReference = new DocumentReference("xwiki", "S", "P");
        // prepare rules to put on the document, with empty list of users and groups
        WritableSecurityRule rule = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.VIEW), RuleState.ALLOW);

        // call the function under test
        this.rightsWriter.saveRules(Arrays.asList(rule), documentReference);

        // get the document that was just modified and assert on it
        XWikiDocument resultDoc =
            this.oldcore.getSpyXWiki().getDocument(documentReference, this.oldcore.getXWikiContext());
        // check that there is a single object set
        assertEquals(1, resultDoc.getXObjects(XWIKI_RIGHTS_CLASS).size());
        BaseObject rightsObj = resultDoc.getXObject(XWIKI_RIGHTS_CLASS);
        // check that the users and groups are set to empty
        assertEquals("", rightsObj.getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("", rightsObj.getLargeStringValue(USERS_PROPERTY));
        // and the rest of the object is set properly, as we asked for
        assertEquals("view", rightsObj.getLargeStringValue(LEVELS_PROPERTY));
        assertEquals(1, rightsObj.getIntValue(ALLOW_PROPERTY));
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

    @Test
    void addRightsOnSpace() throws XWikiException
    {
        SpaceReference spaceReference = new SpaceReference("xwiki", "MySpace");
        DocumentReference adminGroup = new DocumentReference("XWikiAdminGroup", new SpaceReference(XWIKI_SPACE,
            new WikiReference("xwiki")));
        DocumentReference adminUser = new DocumentReference("XWikiAdmin", spaceReference);

        WritableSecurityRule rule = new WritableSecurityRuleImpl(Collections.singletonList(adminGroup),
            Collections.singletonList(adminUser), new RightSet(Right.COMMENT, Right.EDIT, Right.DELETE),
            RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(rule), spaceReference);

        DocumentReference spaceWebPreference = new DocumentReference(XWIKI_WEB_PREFERENCES, spaceReference);

        XWikiDocument spaceWebPreferenceDoc = oldcore.getSpyXWiki().getDocument(spaceWebPreference,
            oldcore.getXWikiContext());

        assertEquals(1, spaceWebPreferenceDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());
        assertEquals("XWiki.XWikiAdminGroup",
            spaceWebPreferenceDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getLargeStringValue(GROUPS_PROPERTY));
        assertEquals("MySpace.XWikiAdmin",
            spaceWebPreferenceDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getLargeStringValue(USERS_PROPERTY));
    }

    @Test
    void addRightsWithSubjectsFromAnotherWikiOnSpace() throws XWikiException
    {
        SpaceReference spaceToSetRights = new SpaceReference("xwiki", "MySpace");

        DocumentReference userReference = new DocumentReference("XWikiAdmin", new SpaceReference("XWiki",
            new WikiReference("subwiki")));

        DocumentReference userReferenceFromSameWiki = new DocumentReference("SimpleUser", new SpaceReference("Space",
            new WikiReference("xwiki")));

        DocumentReference groupReference = new DocumentReference("XWikiAllGroup", new SpaceReference("Space",
            new WikiReference("anotherWiki")));

        WritableSecurityRule writableSecurityRule =
            new WritableSecurityRuleImpl(Collections.singletonList(groupReference),
                Arrays.asList(userReference, userReferenceFromSameWiki), new RightSet(Right.EDIT, Right.VIEW,
                Right.COMMENT), RuleState.DENY);

        rightsWriter.saveRules(Collections.singletonList(writableSecurityRule), spaceToSetRights);

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(new DocumentReference(XWIKI_WEB_PREFERENCES,
            spaceToSetRights), oldcore.getXWikiContext());

        assertEquals("anotherWiki:Space.XWikiAllGroup",
            document.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getLargeStringValue(GROUPS_PROPERTY));

        assertEquals(Arrays.asList("subwiki:XWiki.XWikiAdmin", "Space.SimpleUser"),
            UsersClass.getListFromString(
                document.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).get(0).getLargeStringValue(USERS_PROPERTY)));
    }

    /**
     * Helper function to get the non null objects.
     * 
     * @param classReference
     * @param document
     * @return
     */
    private List<BaseObject> getNonNullObjects(EntityReference classReference, XWikiDocument document)
    {
        return document.getXObjects(classReference).stream().filter(k -> k != null).collect(Collectors.toList());
    }

    /**
     * Helper function to setup mandatory classes on a different subwiki than the main wiki.
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
}
