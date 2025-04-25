package de.governikus.datasign.cookbook.types.response;

public record UserState(State state) {

    public enum State {
        NOT_REGISTERED,
        NOT_READY,
        READY
    }
}
