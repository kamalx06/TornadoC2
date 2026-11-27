import { useMemo } from 'react'
import DOMPurify from 'dompurify'
import { marked } from 'marked'

const TAGS = [
  'p', 'br', 'strong', 'em', 'del', 'code', 'pre', 'blockquote',
  'ul', 'ol', 'li', 'a', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
  'hr', 'table', 'thead', 'tbody', 'tr', 'th', 'td', 'img', 'span'
]
const ATTRS = ['href', 'title', 'src', 'alt', 'class', 'rel', 'target']

let hooked = false
if (!hooked) {
  hooked = true
  DOMPurify.addHook('afterSanitizeAttributes', (node) => {
    if (node.tagName === 'A' && node.getAttribute('href')) {
      node.setAttribute('target', '_blank')
      node.setAttribute('rel', 'noreferrer noopener')
    }
  })
}

marked.setOptions({ gfm: true, breaks: true })

export default function Markdown(props: {
  source: string
  className?: string
}): JSX.Element {
  const html = useMemo(() => {
    const raw = marked.parse(props.source)
    return DOMPurify.sanitize(typeof raw === 'string' ? raw : '',
      { ALLOWED_TAGS: TAGS, ALLOWED_ATTR: ATTRS })
  }, [props.source])
  return (
    <div className={`markdown${props.className ? ` ${props.className}` : ''}`}
      dangerouslySetInnerHTML={{ __html: html }} />
  )
}
