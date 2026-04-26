import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.db.base import Base


class ContributorUser(Base):
    __tablename__ = "contributor_users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Lien obligatoire avec l'organisation (one-to-one)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organisations.id"), 
                    nullable=False, unique=True)
    
    email = Column(String(255), nullable=False, unique=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Ce flag force le contributeur à changer son mot de passe temporaire à la première connexion
    must_change_password = Column(Boolean, default=True, nullable=False)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relation inverse vers l'organisation
    organisation = relationship("Organisation", back_populates="contributor_user")
