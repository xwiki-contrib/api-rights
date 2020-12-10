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

import java.util.List;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.context.Execution;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.contrib.rights.RightsWriter;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.AuthorizationManager;
import org.xwiki.security.authorization.ReadableSecurityRule;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * @version $Id: $
 */
@Component
@Named("rights")
@Singleton
public class RightsAPIService implements ScriptService
{
    @Inject
    private Execution execution;

    @Inject
    private RightsReader rightsReader;

    @Inject
    private RightsWriter rightsWriter;

    @Inject
    private AuthorizationManager authorization;

    // TODO: inject a logger & log the operations.

    /**
     * @param ref
     * @return the list with the rules that are actually applying for @ref.
     */
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        return rightsReader.getActualRules(ref);
    }

    /**
     * @param ref
     * @param withImplied whether implied rules should also be returned or only persisted rules
     * @return the list of security rules that apply to the passed entity
     */
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        return rightsReader.getRules(ref, withImplied);
    }

    /**
     * Saves the passed rules.
     *
     * @param rules the rules to save.
     * @param reference the reference to save rules on. In order to actually save the rules, the reference must be a
     *     Document, Space or a Wiki.
     * @return whether the save was successful or not.
     */
    public boolean saveRules(List<ReadableSecurityRule> rules, EntityReference reference)
    {
        if (authorization.hasAccess(Right.EDIT, getXContext().getUserReference(), reference)) {
            try {
                rightsWriter.saveRules(rules, reference);
                return true;
            } catch (UnsupportedOperationException | IllegalArgumentException | XWikiException e) {
                getXContext().put("message", e.toString());
            }
        }
        return false;
    }

    private XWikiContext getXContext()
    {
        return (XWikiContext) execution.getContext().getProperty("xwikicontext");
    }
}
