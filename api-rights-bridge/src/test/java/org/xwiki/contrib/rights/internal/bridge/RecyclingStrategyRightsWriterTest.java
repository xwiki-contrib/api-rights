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
import java.util.Objects;
import java.util.stream.Collectors;

import javax.inject.Named;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.xwiki.component.manager.ComponentLookupException;
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
import org.xwiki.model.reference.SpaceReference;
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

/**
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class,
    IncrementingObjectNumbersRulesWriter.class, RecyclingObjectsRulesWriter.class})
public class RecyclingStrategyRightsWriterTest
{
    private static final String XWIKI_SPACE = "XWiki";

    private static final String XWIKI_WEB_PREFERENCES = "WebPreferences";

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
    void replaceWithLessRules() throws XWikiException, ComponentLookupException
    {
        SpaceReference spaceReference = new SpaceReference("xwiki", "Space", "Page");
        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumb1 = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Arrays.asList(dumb, dumb1, dumb, dumb1), spaceReference, "recycling");

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

        rightsWriter.saveRules(Collections.singletonList(ruleToCopy), spaceReference, "recycling");

        // The XWikiDocument was changed in the store, need to retrieve it again.
        spaceWebPreferencesDoc = oldcore.getSpyXWiki().getDocument(spaceWebPreferencesRef, oldcore.getXWikiContext());
        // From the entire list of objects, we're interested only in ones that are not null.
        assertEquals(1, getNonNullObjects(XWIKI_GLOBAL_RIGHTS_CLASS, spaceWebPreferencesDoc).size());
        assertEquals(0, getNonNullObjects(XWIKI_GLOBAL_RIGHTS_CLASS, spaceWebPreferencesDoc).get(0).getNumber());
    }

    @Test
    void replaceWithMoreRules() throws XWikiException, ComponentLookupException
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

        WritableSecurityRule dumb = new WritableSecurityRuleImpl(Arrays.asList(group1, group2),
            Arrays.asList(user1, user2), new RightSet(Right.EDIT, Right.COMMENT), RuleState.DENY);

        WritableSecurityRule dumbRight2 = new WritableSecurityRuleImpl(Arrays.asList(group3, group4),
            Collections.singletonList(user3), new RightSet(Right.VIEW, Right.PROGRAM, Right.EDIT), RuleState.DENY);

        rightsWriter.saveRules(Arrays.asList(dumb, dumbRight2), documentReference, "recycling");

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        int noPersistedObjects = 2;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());

        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }

        rightsWriter.saveRules(Arrays.asList(dumbRight2, dumb, dumbRight2, dumbRight2), documentReference, "recycling");

        // The XWikiDocument was changed in the store, need to retrieve it again.
        document = oldcore.getSpyXWiki().getDocument(documentReference, oldcore.getXWikiContext());

        noPersistedObjects = 4;
        assertEquals(noPersistedObjects, document.getXObjects(XWIKI_RIGHTS_CLASS).size());
        for (int i = 0; i < noPersistedObjects; ++i) {
            assertEquals(i, document.getXObjects(XWIKI_RIGHTS_CLASS).get(i).getNumber());
        }
    }

    @Test
    void testReplaceWithSingleRuleOnSpace() throws XWikiException, ComponentLookupException
    {
        replaceWithSingleRule(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES));
    }

    @Test
    void testReplaceWithSingleRuleOnPage() throws XWikiException, ComponentLookupException
    {
        replaceWithSingleRule(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "myPage"));
    }

    private void replaceWithSingleRule(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects) throws XWikiException, ComponentLookupException
    {
        // replace a rule and check that it's in the same object & test if it copied all the fields
        WritableSecurityRule dumbRule = new WritableSecurityRuleImpl(Collections.emptyList(), Collections.emptyList(),
            new RightSet(Right.EDIT, Right.COMMENT, Right.VIEW), RuleState.DENY);

        rightsWriter.saveRules(Collections.singletonList(dumbRule), whereToSaveRules, "recycling");

        XWikiDocument document = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertNotNull(document);
        assertEquals(1, document.getXObjects(rightsClassReference).size());
        List<BaseObject> objects = document.getXObjects(rightsClassReference);
        BaseObject right = objects.get(0);

        // before
        assertEquals(Collections.emptyList(), UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.emptyList(), GroupsClass.getListFromString(right.getLargeStringValue("groups")));
        assertEquals(Arrays.asList("view", "edit", "comment"),
            LevelsClass.getListFromString(right.getLargeStringValue("levels")));
        assertEquals(0, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));

        // replace rule with another rule
        DocumentReference adminUserDocRef = new DocumentReference("xwiki", "XWiki", "XWikiAdmin");
        WritableSecurityRule dumbRule2 = new WritableSecurityRuleImpl(Collections.singletonList(adminUserDocRef),
            Collections.singletonList(adminUserDocRef), new RightSet(Right.VIEW), RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(dumbRule2), whereToSaveRules, "recycling");

        document = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertNotNull(document);
        assertEquals(1, document.getXObjects(rightsClassReference).size());
        objects = document.getXObjects(rightsClassReference);
        right = objects.get(0);

        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            UsersClass.getListFromString(right.getLargeStringValue("users")));
        assertEquals(Collections.singletonList("XWiki.XWikiAdmin"),
            GroupsClass.getListFromString(right.getLargeStringValue("groups")));
        assertEquals(Collections.singletonList("view"),
            LevelsClass.getListFromString(right.getLargeStringValue("levels")));
        assertEquals(1, right.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
    }

    /**
     * Replace a rule with another rule that uses null for one of the subjects (groups or users) and make sure there are
     * no leftovers in the recycled object.
     *
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    @Test
    void testReplaceWithRuleWithNullSubjectUsers() throws XWikiException, ComponentLookupException
    {
        EntityReference saveOn = new SpaceReference("xwiki", "Space", "MySpace");
        WritableSecurityRule fullySetRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.ALLOW);

        DocumentReference testedDocReference =
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES);

        rightsWriter.saveRules(Collections.singletonList(fullySetRule), saveOn, "recycling");

        XWikiDocument testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // before
        BaseObject testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 1, testedObj);

        // replace rule with another rule, that has a null subject (e.g. users)
        WritableSecurityRule nullSubjectRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")), null,
            new RightSet(Right.EDIT), RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(nullSubjectRule), saveOn, "recycling");

        testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // after: the users are empty, group stays the same as it wasn't changed and rights change also
        testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "", "edit", 1, testedObj);
    }

    /**
     * Replace a rule with another rule that uses null for one of the subjects (groups or users) and make sure there are
     * no leftovers in the recycled object.
     *
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    @Test
    void testReplaceWithRuleWithNullSubjectGroups() throws XWikiException, ComponentLookupException
    {
        EntityReference saveOn = new SpaceReference("xwiki", "Space", "MySpace");
        WritableSecurityRule fullySetRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.ALLOW);

        DocumentReference testedDocReference =
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES);

        rightsWriter.saveRules(Collections.singletonList(fullySetRule), saveOn, "recycling");

        XWikiDocument testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // before
        BaseObject testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 1, testedObj);

        // replace rule with another rule, that has a null subject (e.g. users)
        WritableSecurityRule nullSubjectRule = new WritableSecurityRuleImpl(null,
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.EDIT),
            RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(nullSubjectRule), saveOn, "recycling");

        testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // after: the groups are empty, user stays the same as it wasn't changed and rights change also
        testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("", "XWiki.Admin", "edit", 1, testedObj);
    }

    /**
     * Replace a rule with another rule that uses an empty list for one of the subjects (groups or users) and make sure
     * there are no leftovers in the recycled object.
     *
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    @Test
    void testReplaceWithRuleWithEmptySubject() throws XWikiException, ComponentLookupException
    {
        EntityReference saveOn = new SpaceReference("xwiki", "Space", "MySpace");
        WritableSecurityRule fullySetRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.ALLOW);

        DocumentReference testedDocReference =
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES);

        rightsWriter.saveRules(Collections.singletonList(fullySetRule), saveOn, "recycling");

        XWikiDocument testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // before
        BaseObject testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 1, testedObj);

        // replace rule with another rule, that has an empty list subject (e.g. groups)
        WritableSecurityRule emptySubjectRule = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Administrator")),
            new RightSet(Right.EDIT), RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(emptySubjectRule), saveOn, "recycling");

        testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // after: the groups are empty, user and rights change, as they changed in the rule
        testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("", "XWiki.Administrator", "edit", 1, testedObj);
    }

    /**
     * Replace a rule with another rule that uses null for the rights set and make sure there are no leftovers in the
     * recycled object.
     *
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    @Test
    void testReplaceWithRuleWithNullRights() throws XWikiException, ComponentLookupException
    {
        EntityReference saveOn = new SpaceReference("xwiki", "Space", "MySpace");
        WritableSecurityRule fullySetRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.ALLOW);

        DocumentReference testedDocReference =
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES);

        rightsWriter.saveRules(Collections.singletonList(fullySetRule), saveOn, "recycling");

        XWikiDocument testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // before
        BaseObject testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 1, testedObj);

        // replace rule with another rule, that has a null subject (e.g. users)
        WritableSecurityRule nullSubjectRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), null, RuleState.ALLOW);

        rightsWriter.saveRules(Collections.singletonList(nullSubjectRule), saveOn, "recycling");

        testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // after: all stays the same but rights are emptied.
        testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "", 1, testedObj);
    }

    /**
     * Replace a rule with another rule that uses null for the allow and check that it's set as allowing, since the
     * default for the allow is true if a rule doesn't have the allow set.
     *
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    @Test
    void testReplaceWithRuleWithNullAllow() throws XWikiException, ComponentLookupException
    {
        EntityReference saveOn = new SpaceReference("xwiki", "Space", "MySpace");
        WritableSecurityRule fullySetRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            RuleState.DENY);

        DocumentReference testedDocReference =
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES);

        rightsWriter.saveRules(Collections.singletonList(fullySetRule), saveOn, "recycling");

        XWikiDocument testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // before
        BaseObject testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 0, testedObj);

        // replace rule with another rule, that has a null subject (e.g. users)
        WritableSecurityRule nullSubjectRule = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAllGroup")),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.VIEW),
            null);

        rightsWriter.saveRules(Collections.singletonList(nullSubjectRule), saveOn, "recycling");

        testedDoc = oldcore.getSpyXWiki().getDocument(testedDocReference, oldcore.getXWikiContext());
        assertNotNull(testedDoc);
        assertEquals(1, testedDoc.getXObjects(XWIKI_GLOBAL_RIGHTS_CLASS).size());

        // all
        testedObj = testedDoc.getXObject(XWIKI_GLOBAL_RIGHTS_CLASS);
        assertObject("XWiki.XWikiAllGroup", "XWiki.Admin", "view", 1, testedObj);
    }

    /**
     * Helps to assert the state of an object. Since it compares the properties as strings, use only for single values
     * of the tested metadata, since you cannot rely on the order of serialization.
     *
     * @param groups expected groups, as string
     * @param users expected users, as string
     * @param rights expected rights, as string
     * @param allow expected allow as number (1 for allow, 0 for deny)
     * @param testedObj the object to test previous values on
     */
    private void assertObject(String groups, String users, String rights, int allow, BaseObject testedObj)
    {
        assertEquals(users, testedObj.getLargeStringValue(XWikiConstants.USERS_FIELD_NAME));
        assertEquals(groups, testedObj.getLargeStringValue(XWikiConstants.GROUPS_FIELD_NAME));
        assertEquals(rights, testedObj.getLargeStringValue(XWikiConstants.LEVELS_FIELD_NAME));
        assertEquals(allow, testedObj.getIntValue(XWikiConstants.ALLOW_FIELD_NAME));
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
        return document.getXObjects(classReference).stream().filter(Objects::nonNull).collect(Collectors.toList());
    }
}
