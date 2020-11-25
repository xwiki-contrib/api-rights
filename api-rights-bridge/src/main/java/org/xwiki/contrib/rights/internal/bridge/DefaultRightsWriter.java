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
import java.util.List;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.context.Execution;
import org.xwiki.contrib.rights.internal.AbstractRightsWriter;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;
import org.xwiki.security.authorization.RuleState;
import org.xwiki.security.internal.XWikiConstants;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;

/**
 * @version $Id$
 */
@Component
@Singleton
public class DefaultRightsWriter extends AbstractRightsWriter
{
    private static final String DEFAULT_STRING_DELIMITER = ",";

    @Inject
    private Execution execution;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private EntityReferenceSerializer<String> entityReferenceSerializer;

    /**
     * One rule will correspond to one right object.
     * <p>
     * TODO: is void the right type for return? Any others possibilities? Is there any reason to change it? Maybe the
     * number of saved rules? Maybe the rules themself (as List<BaseObject>)?
     *
     * @see org.xwiki.contrib.rights.RightsWriter#saveRules(java.util.List, org.xwiki.model.reference.EntityReference)
     */
    @Override
    public void saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
    {
        // TODO: drop the existing rules.

        List<BaseObject> rights = new ArrayList<>();
        if (null != reference) {
            for (ReadableSecurityRule rule : rules) {
                // create object corresponding to the rule
                try {
                    BaseObject ruleObject = createRightObjectFromRule(rule);
                    if (null != ruleObject) {
                        ruleObject.setOwnerDocument(getXWiki().getDocument(reference, getXContext()));
                        rights.add(ruleObject);
                    }
                } catch (XWikiException e) {
                    e.printStackTrace();
                }
            }
            // TODO: Save the rights.
            switch (reference.getType()) {
                case PAGE:
                    // TODO:
                case SPACE:
                    // TODO: set the rights for the entire space
                case WIKI:
                    // TODO: set the rights for the entire wiki
                default:
                    break;
            }
        }
    }

    /**
     * @return the xcontext
     */
    private XWikiContext getXContext()
    {
        return (XWikiContext) execution.getContext().getProperty("xwikicontext");
    }

    /**
     * @return the XWiki object
     */
    private XWiki getXWiki()
    {
        return getXContext().getWiki();
    }

    /**
     * @param rule for which the BaseObject will be created
     * @return a BaseObject with XWikiRights XClass, from passed @rule
     */
    private BaseObject createRightObjectFromRule(ReadableSecurityRule rule)
    {
        try {
            DocumentReference rightsClass = documentReferenceResolver.resolve("XWiki.XWikiRights");
            // TODO: could the context be null? If so, in what situation?
            BaseObject object = BaseClass.newCustomClassInstance(rightsClass, getXContext());
            if (null != rule.getState()) {
                // TODO: this checking won't be anymore necessary after deciding if the state of the rule can be or
                //  not a null.
                object.setIntValue(XWikiConstants.ALLOW_FIELD_NAME,
                    rule.getState().getValue() == RuleState.DENY.getValue() ? 0 : 1);
            }

            // How to set extra parameters? e.g. multiple select, validation message, use suggest?

            // Do we have a proper manner to handle lists (any kind of: users, rights, levels, groups) in XObjects?
            // TODO: mention why we do it like this.
            object.setLargeStringValue("users", rule.getUsers().stream()
                .map(k -> entityReferenceSerializer.serialize(k))
                .collect(Collectors.joining(DEFAULT_STRING_DELIMITER))
            );

            object.setLargeStringValue("groups", rule.getGroups().stream()
                .map(k -> entityReferenceSerializer.serialize(k))
                .collect(Collectors.joining(DEFAULT_STRING_DELIMITER))
            );

            object.setLargeStringValue("levels", rule.getRights().stream()
                .map(Right::getName)
                .collect(Collectors.joining(DEFAULT_STRING_DELIMITER))
            );
            return object;
        } catch (XWikiException e) {
            e.printStackTrace();
        }
        return null;
    }
}
