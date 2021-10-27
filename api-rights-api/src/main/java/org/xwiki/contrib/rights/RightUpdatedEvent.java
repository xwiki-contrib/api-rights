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
package org.xwiki.contrib.rights;

import org.xwiki.observation.event.Event;
import org.xwiki.stability.Unstable;

/**
 * Event triggered when a right has been updated.
 *
 * Along with the event those information are sent:
 * <ul>
 *     <li>source: the {@link org.xwiki.security.SecurityReference} of the entity impacted by the right update</li>
 *     <li>data: a {@link org.apache.commons.lang3.tuple.Pair} of
 *      {@link java.util.List<org.xwiki.security.authorization.ReadableSecurityRule>} with the left part being the
 *      rules before the update, and the right part the rules after.</li>
 * </ul>
 *
 * @version $Id$
 * @since 2.0
 */
@Unstable
public class RightUpdatedEvent implements Event
{
    @Override
    public boolean matches(Object otherEvent)
    {
        return otherEvent instanceof RightUpdatedEvent;
    }
}
