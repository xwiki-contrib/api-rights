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

import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.rights.RightsReader;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.security.authorization.ReadableSecurityRule;

/**
 * @version $Id$
 */
@Component
@Singleton
public class DefaultRightsReader implements RightsReader
{

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getRules(org.xwiki.model.reference.EntityReference, java.lang.Boolean)
     */
    @Override
    public List<ReadableSecurityRule> getRules(EntityReference ref, Boolean withImplied)
    {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getPersistedRules(org.xwiki.model.reference.EntityReference)
     */
    @Override
    public List<ReadableSecurityRule> getPersistedRules(EntityReference ref)
    {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * {@inheritDoc}
     *
     * @see org.xwiki.contrib.rights.RightsReader#getActualRules(org.xwiki.model.reference.EntityReference)
     */
    @Override
    public List<ReadableSecurityRule> getActualRules(EntityReference ref)
    {
        // TODO Auto-generated method stub
        return null;
    }
}
