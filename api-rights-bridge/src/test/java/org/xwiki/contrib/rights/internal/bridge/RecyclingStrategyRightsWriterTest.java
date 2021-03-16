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
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.contrib.rights.WritableSecurityRule;
import org.xwiki.contrib.rights.internal.DefaultRightsWriter;
import org.xwiki.contrib.rights.internal.IncrementingObjectNumbersRulesWriter;
import org.xwiki.contrib.rights.internal.RecyclingObjectsRulesWriter;
import org.xwiki.contrib.rights.internal.WritableSecurityRuleImpl;
import org.xwiki.job.event.status.JobProgressManager;
import org.xwiki.localization.ContextualLocalizationManager;
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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @version $Id$
 */
@OldcoreTest
@ReferenceComponentList
@ComponentList({XWikiGlobalRightsDocumentInitializer.class, XWikiRightsDocumentInitializer.class,
    IncrementingObjectNumbersRulesWriter.class, RecyclingObjectsRulesWriter.class})
public class RecyclingStrategyRightsWriterTest extends AbstractRightsWriterTest
{
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

    @Test
    void testIgnoreNullObjectOnRecyclingOnPage() throws XWikiException, ComponentLookupException
    {
        ignoreNullObjectOnRecycling(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "myPage"));
    }

    @Test
    void testIgnoreNullObjectOnRecyclingOnSpace() throws XWikiException, ComponentLookupException
    {
        ignoreNullObjectOnRecycling(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES));
    }

    @Test
    void testCleanupNullObjectsOnRecyclingOnPage() throws XWikiException, ComponentLookupException
    {
        cleanupNullObjectsOnRecycling(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "myPage"));
    }

    @Test
    void testCleanupNullObjectsOnRecyclingOnSpace() throws XWikiException, ComponentLookupException
    {
        cleanupNullObjectsOnRecycling(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES));
    }

    @Test
    void testRecycleExactNonNullObjectsOnPage() throws XWikiException, ComponentLookupException
    {
        recycleAllNonNullObjects(new DocumentReference("xwiki", "space", "Obj0IsNull"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "Obj0IsNull"), 0);
        recycleAllNonNullObjects(new DocumentReference("xwiki", "space", "Obj1IsNull"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "Obj1IsNull"), 1);
        recycleAllNonNullObjects(new DocumentReference("xwiki", "space", "Obj2IsNull"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "Obj2IsNull"), 2);
    }

    @Test
    void testRecycleExactNonNullObjectsOnSpace() throws XWikiException, ComponentLookupException
    {
        recycleAllNonNullObjects(new SpaceReference("xwiki", "Space", "Obj0IsNull"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "Obj0IsNull"), XWIKI_WEB_PREFERENCES), 0);
        recycleAllNonNullObjects(new SpaceReference("xwiki", "Space", "Obj1IsNull"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "Obj1IsNull"), XWIKI_WEB_PREFERENCES), 1);
        recycleAllNonNullObjects(new SpaceReference("xwiki", "Space", "Obj2IsNull"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "Obj2IsNull"), XWIKI_WEB_PREFERENCES), 2);
    }

    @Test
    void testNotEnoughNonNullObjectsOnPage() throws XWikiException, ComponentLookupException
    {
        notEnoughRecyclableObjects(new DocumentReference("xwiki", "space", "myPage"), XWIKI_RIGHTS_CLASS,
            new DocumentReference("xwiki", "space", "myPage"));
    }

    @Test
    void testNotEnoughNonNullObjectsOnSpace() throws XWikiException, ComponentLookupException
    {
        notEnoughRecyclableObjects(new SpaceReference("xwiki", "Space", "MySpace"), XWIKI_GLOBAL_RIGHTS_CLASS,
            new DocumentReference("xwiki", Arrays.asList("Space", "MySpace"), XWIKI_WEB_PREFERENCES));
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
     * Tests that if a null object is in the objects array, it's correctly ignored upon recycling. Will be used to test
     * the case on page and space.
     *
     * @param whereToSaveRules entity to save rules on (page or space)
     * @param rightsClassReference the class of the rules (depending on whether it's space or page)
     * @param whereToCheckObjects the document where rules are saved (depending on whether it's space or page)
     * @throws XWikiException in case anything goes wrong
     * @throws ComponentLookupException in case anything goes wrong
     */
    private void ignoreNullObjectOnRecycling(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects) throws XWikiException, ComponentLookupException
    {
        // 1. save two rules
        WritableSecurityRule ruleOne = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
            Collections.emptyList(), new RightSet(Right.VIEW), RuleState.ALLOW);
        WritableSecurityRule ruleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Admin")), new RightSet(Right.EDIT),
            RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(ruleOne, ruleTwo), whereToSaveRules, "recycling");

        // check that 2 objects were created, and that they're not null
        XWikiDocument checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(2, checkedDoc.getXObjects(rightsClassReference).size());
        assertEquals(2, getNonNullObjects(rightsClassReference, checkedDoc).size());

        // 2. alter the document by other means and remove its first object
        XWikiDocument docToAlter = checkedDoc.clone();
        BaseObject firstObject = docToAlter.getXObjects(rightsClassReference).get(0);
        docToAlter.removeXObject(firstObject);
        this.oldcore.getSpyXWiki().saveDocument(docToAlter, this.oldcore.getXWikiContext());
        // check that indeed the first object is null now
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(2, checkedDoc.getXObjects(rightsClassReference).size());
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(0));

        // 3. update the rules with the 2 rules (but in reverse order)
        rightsWriter.saveRules(Arrays.asList(ruleTwo, ruleOne), whereToSaveRules, "recycling");
        // and check that it doesn't fail and rules are saved correctly
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        // there are 2 non-null objects but 3 in total, with the first one still being null
        assertEquals(2, getNonNullObjects(rightsClassReference, checkedDoc).size());
        assertEquals(3, checkedDoc.getXObjects(rightsClassReference).size());
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(0));

        // check that the 2 rules are matched by the objects in this document, regardless of the order
        boolean matchesRuleOne = false;
        boolean matchesRuleTwo = false;
        for (BaseObject rightObj : checkedDoc.getXObjects(rightsClassReference)) {
            if (rightObj != null) {
                matchesRuleOne = matchesRuleOne || matchesRule("XWiki.XWikiAdminGroup", "", "view", 1, rightObj);
                matchesRuleTwo = matchesRuleTwo || matchesRule("", "XWiki.Admin", "edit", 1, rightObj);
            }
        }
        assertTrue(matchesRuleOne);
        assertTrue(matchesRuleTwo);
    }

    /**
     * Tests that if a null object is in the objects array, it's correctly "removed" upon recycling. Actually, it tests
     * that if there is a non-null object after the null one it also gets cleaned up properly.
     *
     * @param whereToSaveRules entity to save rules on (page or space)
     * @param rightsClassReference the class of the rules (depending on whether it's space or page)
     * @param whereToCheckObjects the document where rules are saved (depending on whether it's space or page)
     * @throws XWikiException in case anything goes wrong
     * @throws ComponentLookupException in case anything goes wrong
     */
    private void cleanupNullObjectsOnRecycling(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects) throws XWikiException, ComponentLookupException
    {
        // 1. save four rules
        WritableSecurityRule ruleOne = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "One")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Two")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleThree = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Three")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleFour = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Four")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(ruleOne, ruleTwo, ruleThree, ruleFour), whereToSaveRules, "recycling");

        // check that 4 objects were created, and that they're not null
        XWikiDocument checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(4, checkedDoc.getXObjects(rightsClassReference).size());
        assertEquals(4, getNonNullObjects(rightsClassReference, checkedDoc).size());

        // 2. alter the document by other means and remove its third object
        XWikiDocument docToAlter = checkedDoc.clone();
        BaseObject thirdObject = docToAlter.getXObjects(rightsClassReference).get(2);
        docToAlter.removeXObject(thirdObject);
        this.oldcore.getSpyXWiki().saveDocument(docToAlter, this.oldcore.getXWikiContext());
        // check that indeed the third object is null now
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(4, checkedDoc.getXObjects(rightsClassReference).size());
        assertEquals(3, getNonNullObjects(rightsClassReference, checkedDoc).size());
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(2));

        // 3. update the rules with one new rule
        rightsWriter
            .saveRules(
                Arrays.asList(new WritableSecurityRuleImpl(
                    Collections.singletonList(new DocumentReference("xwiki", "XWiki", "XWikiAdminGroup")),
                    Collections.emptyList(), new RightSet(Right.EDIT), RuleState.ALLOW)),
                whereToSaveRules, "recycling");
        // and check that it doesn't fail and the rule is saved correctly
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(1, getNonNullObjects(rightsClassReference, checkedDoc).size());
        BaseObject rightObj = checkedDoc.getXObject(rightsClassReference);
        assertObject("XWiki.XWikiAdminGroup", "", "edit", 1, rightObj);
    }

    /**
     * Tests that all objects are recycled correctly if the same number of rules are saved, regardless of the fact that
     * the numbers have non-contiguous numbers.
     *
     * @param whereToSaveRules entity to save rules on (page or space)
     * @param rightsClassReference the class of the rules (depending on whether it's space or page)
     * @param whereToCheckObjects the document where rules are saved (depending on whether it's space or page)
     * @throws XWikiException in case anything goes wrong
     * @throws ComponentLookupException in case anything goes wrong
     */
    private void recycleAllNonNullObjects(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects, int positionOfNullObject) throws XWikiException, ComponentLookupException
    {
        // 1. save three rules
        WritableSecurityRule ruleOne = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "One")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Two")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleThree = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Three")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(ruleOne, ruleTwo, ruleThree), whereToSaveRules, "recycling");

        // check that 3 objects were created, and that they're not null
        XWikiDocument checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(3, checkedDoc.getXObjects(rightsClassReference).size());
        assertEquals(3, getNonNullObjects(rightsClassReference, checkedDoc).size());

        // 2. alter the document by other means and remove the object on the desired position
        XWikiDocument docToAlter = checkedDoc.clone();
        BaseObject thirdObject = docToAlter.getXObjects(rightsClassReference).get(positionOfNullObject);
        docToAlter.removeXObject(thirdObject);
        this.oldcore.getSpyXWiki().saveDocument(docToAlter, this.oldcore.getXWikiContext());
        // check that indeed the removed object is null now
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(2, getNonNullObjects(rightsClassReference, checkedDoc).size());
        // if the position to remove is not the last one, we also expect the null to remain
        // in test env the null will also remain on the last position but not in real case
        if (positionOfNullObject != 2) {
            assertEquals(3, checkedDoc.getXObjects(rightsClassReference).size());
            assertNull(checkedDoc.getXObjects(rightsClassReference).get(positionOfNullObject));
        }

        // 3. update the rules with two rules, the number of remaining non-null objects
        WritableSecurityRule newRuleOne = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "NewOne")), new RightSet(Right.COMMENT),
            RuleState.ALLOW);
        WritableSecurityRule newRuleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "NewTwo")), new RightSet(Right.EDIT),
            RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(newRuleOne, newRuleTwo), whereToSaveRules, "recycling");
        // and check that it doesn't fail and the rules are saved correctly
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(2, getNonNullObjects(rightsClassReference, checkedDoc).size());
        // if the position to remove is not the last one, we also expect the null to remain
        // in test env the null will also remain on the last position but not in real case
        if (positionOfNullObject != 2) {
            assertEquals(3, checkedDoc.getXObjects(rightsClassReference).size());
            assertNull(checkedDoc.getXObjects(rightsClassReference).get(positionOfNullObject));
        }
        // and check that the rules are the expected ones, regardless of the order
        boolean matchesRuleOne = false;
        boolean matchesRuleTwo = false;
        for (BaseObject rightObj : checkedDoc.getXObjects(rightsClassReference)) {
            if (rightObj != null) {
                matchesRuleOne = matchesRuleOne || matchesRule("", "XWiki.NewOne", "comment", 1, rightObj);
                matchesRuleTwo = matchesRuleTwo || matchesRule("", "XWiki.NewTwo", "edit", 1, rightObj);
            }
        }
        assertTrue(matchesRuleOne);
        assertTrue(matchesRuleTwo);
    }

    /**
     * Tests that the recycling works to add a new object because there are not enough non null objects (although there
     * are plenty of objects).
     *
     * @param whereToSaveRules
     * @param rightsClassReference
     * @param whereToCheckObjects
     * @throws XWikiException
     * @throws ComponentLookupException
     */
    private void notEnoughRecyclableObjects(EntityReference whereToSaveRules, EntityReference rightsClassReference,
        DocumentReference whereToCheckObjects) throws XWikiException, ComponentLookupException
    {
        // 1. save four rules
        WritableSecurityRule ruleOne = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "One")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Two")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleThree = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Three")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        WritableSecurityRule ruleFour = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "Four")), new RightSet(Right.VIEW),
            RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(ruleOne, ruleTwo, ruleThree, ruleFour), whereToSaveRules, "recycling");

        // check that 4 objects were created, and that they're not null
        XWikiDocument checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(4, checkedDoc.getXObjects(rightsClassReference).size());
        assertEquals(4, getNonNullObjects(rightsClassReference, checkedDoc).size());

        // 2. alter the document by other means and remove its first and third objects
        XWikiDocument docToAlter = checkedDoc.clone();
        BaseObject firstObject = docToAlter.getXObjects(rightsClassReference).get(0);
        docToAlter.removeXObject(firstObject);
        BaseObject thirdObject = docToAlter.getXObjects(rightsClassReference).get(2);
        docToAlter.removeXObject(thirdObject);
        this.oldcore.getSpyXWiki().saveDocument(docToAlter, this.oldcore.getXWikiContext());
        // check that indeed the first object is null now and so is the third one
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        assertEquals(4, checkedDoc.getXObjects(rightsClassReference).size());
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(0));
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(2));

        // 3. update the rules with 3 new rules
        WritableSecurityRule newRuleOne = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "NewOne")), new RightSet(Right.COMMENT),
            RuleState.ALLOW);
        WritableSecurityRule newRuleTwo = new WritableSecurityRuleImpl(Collections.emptyList(),
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "NewTwo")), new RightSet(Right.EDIT),
            RuleState.DENY);
        WritableSecurityRule newRuleThree = new WritableSecurityRuleImpl(
            Collections.singletonList(new DocumentReference("xwiki", "XWiki", "NewThreeG")), Collections.emptyList(),
            new RightSet(Right.ADMIN), RuleState.ALLOW);
        rightsWriter.saveRules(Arrays.asList(newRuleOne, newRuleTwo, newRuleThree), whereToSaveRules, "recycling");
        // and check that it doesn't fail and rules are saved correctly
        checkedDoc = oldcore.getSpyXWiki().getDocument(whereToCheckObjects, oldcore.getXWikiContext());
        // there are 3 non-null objects but 5 in total, with the holes still being preserved
        assertEquals(3, getNonNullObjects(rightsClassReference, checkedDoc).size());
        assertEquals(5, checkedDoc.getXObjects(rightsClassReference).size());
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(0));
        assertNull(checkedDoc.getXObjects(rightsClassReference).get(2));

        // check that the 2 rules are matched by the objects in this document, regardless of the order
        boolean matchesRuleOne = false;
        boolean matchesRuleTwo = false;
        boolean matchesRuleThree = false;
        for (BaseObject rightObj : checkedDoc.getXObjects(rightsClassReference)) {
            if (rightObj != null) {
                matchesRuleOne = matchesRuleOne || matchesRule("", "XWiki.NewOne", "comment", 1, rightObj);
                matchesRuleTwo = matchesRuleTwo || matchesRule("", "XWiki.NewTwo", "edit", 0, rightObj);
                matchesRuleThree = matchesRuleThree || matchesRule("XWiki.NewThreeG", "", "admin", 1, rightObj);
            }
        }
        assertTrue(matchesRuleOne);
        assertTrue(matchesRuleTwo);
        assertTrue(matchesRuleThree);
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
}
